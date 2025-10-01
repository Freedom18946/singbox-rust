#![cfg_attr(feature = "strict_warnings", deny(warnings))]

#[cfg(not(feature = "bench"))]
fn main() {
    tracing::warn!(target: "app::bench", "built without `--features bench` — stub running");
    tracing::info!(target: "app::bench", "Set SB_BENCH=1 and enable `bench` feature to run benchmarks");
}

#[cfg(feature = "bench")]
use std::net::SocketAddr;
#[cfg(feature = "bench")]
use std::time::{Duration, Instant};

#[cfg(feature = "bench")]
use hdrhistogram::Histogram;
#[cfg(feature = "bench")]
use serde_json::json;
#[cfg(feature = "bench")]
use tokio::time::timeout;
#[cfg(feature = "bench")]
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
#[cfg(feature = "bench")]
use trust_dns_proto::rr::{Name, RecordType};
#[cfg(feature = "bench")]
use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};

#[cfg(feature = "bench")]
#[tokio::main]
async fn main() {
    if std::env::var("SB_BENCH").ok().as_deref() != Some("1") {
        tracing::warn!(target: "app::bench", "SB_BENCH!=1, exit");
        return;
    }

    let runs = std::env::var("SB_BENCH_N")
        .or_else(|_| std::env::var("SB_BENCH_RUNS"))
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(200);

    let tcp_target = std::env::var("SB_BENCH_TCP").unwrap_or_else(|_| "127.0.0.1:7".to_string());
    let udp_target = std::env::var("SB_BENCH_UDP").unwrap_or_else(|_| "127.0.0.1:9099".to_string());
    let dns_target = std::env::var("SB_BENCH_DNS").unwrap_or_else(|_| "127.0.0.1:53".to_string());
    let dns_name =
        std::env::var("SB_BENCH_DNS_NAME").unwrap_or_else(|_| "example.com.".to_string());

    let tcp = bench_tcp(&tcp_target, runs).await;
    let udp = bench_udp(&udp_target, runs).await;
    let dns = bench_dns(&dns_target, &dns_name, runs).await;

    let report = json!({
        "tcp_connect_ms": tcp,
        "udp_rtt_ms": udp,
        "dns_rtt_ms": dns,
    });

    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

#[cfg(feature = "bench")]
async fn bench_tcp(addr: &str, runs: usize) -> serde_json::Value {
    let target: SocketAddr = addr.parse().expect("invalid SB_BENCH_TCP address");
    let mut hist = histogram();

    let par: usize = std::env::var("SB_BENCH_PAR")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    let rounds = runs.div_ceil(par);
    for r in 0..rounds {
        let mut futs = Vec::new();
        for i in 0..par {
            if r * par + i >= runs {
                break;
            }
            futs.push(tokio::spawn(async move {
                let started = Instant::now();
                let attempt = tokio::net::TcpStream::connect(target);
                let _ = timeout(Duration::from_secs(2), attempt).await;
                started.elapsed().as_millis() as u64
            }));
        }
        for f in futs {
            if let Ok(ms) = f.await {
                let _ = hist.record(ms);
            }
        }
    }

    #[cfg(feature = "metrics")]
    {
        use metrics::gauge;
        gauge!("bench_tcp_count").set(hist.len() as f64);
    }

    let json = histogram_json(&hist);
    if let Ok(path) = std::env::var("SB_BENCH_CSV") {
        let csv_content = format!(
            "p50,p90,p99,max,min\n{},{},{},{},{}\n",
            json["p50"], json["p90"], json["p99"], json["max"], json["min"]
        );
        let _ = std::fs::write(format!("{}_tcp", path), csv_content);
    }
    json
}

#[cfg(feature = "bench")]
async fn bench_udp(addr: &str, runs: usize) -> serde_json::Value {
    let target: SocketAddr = addr.parse().expect("invalid SB_BENCH_UDP address");
    let _sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("failed to bind UDP probe socket");
    let mut hist = histogram();

    let par: usize = std::env::var("SB_BENCH_PAR")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let payload_size: usize = std::env::var("SB_BENCH_PAYLOAD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);

    let rounds = runs.div_ceil(par);
    for r in 0..rounds {
        let mut futs = Vec::new();
        for i in 0..par {
            if r * par + i >= runs {
                break;
            }
            // Create a new socket for each parallel task
            futs.push(tokio::spawn(async move {
                let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
                    .await
                    .expect("failed to bind socket");
                let msg = vec![(i % 256) as u8; payload_size];
                let started = Instant::now();
                let _ = sock.send_to(&msg, target).await;
                let mut buf = [0u8; 2048];
                let _ = timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await;
                started.elapsed().as_millis() as u64
            }));
        }
        for f in futs {
            if let Ok(ms) = f.await {
                let _ = hist.record(ms);
            }
        }
    }

    #[cfg(feature = "metrics")]
    {
        use metrics::gauge;
        gauge!("bench_udp_count").set(hist.len() as f64);
    }

    let json = histogram_json(&hist);
    if let Ok(path) = std::env::var("SB_BENCH_CSV") {
        let csv_content = format!(
            "p50,p90,p99,max,min\n{},{},{},{},{}\n",
            json["p50"], json["p90"], json["p99"], json["max"], json["min"]
        );
        let _ = std::fs::write(path, csv_content);
    }
    json
}

#[cfg(feature = "bench")]
async fn bench_dns(addr: &str, qname: &str, runs: usize) -> serde_json::Value {
    let target: SocketAddr = addr.parse().expect("invalid SB_BENCH_DNS address");
    let name = Name::from_ascii(qname).expect("invalid SB_BENCH_DNS_NAME");
    let mut hist = histogram();

    let par: usize = std::env::var("SB_BENCH_PAR")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    let rounds = runs.div_ceil(par);
    for r in 0..rounds {
        let mut futs = Vec::new();
        for i in 0..par {
            if r * par + i >= runs {
                break;
            }
            let name = name.clone();
            futs.push(tokio::spawn(async move {
                let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
                    .await
                    .expect("failed to bind DNS socket");
                let mut msg = Message::new();
                msg.set_id((i & 0xffff) as u16);
                msg.set_op_code(OpCode::Query);
                msg.set_message_type(MessageType::Query);
                msg.set_recursion_desired(true);
                msg.add_query(Query::query(name, RecordType::A));
                let mut data = Vec::with_capacity(64);
                msg.emit(&mut BinEncoder::new(&mut data))
                    .expect("failed to encode DNS query");

                let started = Instant::now();
                let _ = sock.send_to(&data, target).await;
                let mut buf = [0u8; 512];
                let _ = timeout(Duration::from_secs(1), sock.recv_from(&mut buf)).await;
                started.elapsed().as_millis() as u64
            }));
        }
        for f in futs {
            if let Ok(ms) = f.await {
                let _ = hist.record(ms);
            }
        }
    }

    #[cfg(feature = "metrics")]
    {
        use metrics::gauge;
        gauge!("bench_dns_count").set(hist.len() as f64);
    }

    let json = histogram_json(&hist);
    if let Ok(path) = std::env::var("SB_BENCH_CSV") {
        let csv_content = format!(
            "p50,p90,p99,max,min\n{},{},{},{},{}\n",
            json["p50"], json["p90"], json["p99"], json["max"], json["min"]
        );
        let _ = std::fs::write(format!("{}_dns", path), csv_content);
    }
    json
}

#[cfg(feature = "bench")]
fn histogram() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 60_000, 3).expect("failed to create histogram")
}

#[cfg(feature = "bench")]
fn histogram_json(hist: &Histogram<u64>) -> serde_json::Value {
    json!({
        "p50": hist.value_at_quantile(0.50),
        "p90": hist.value_at_quantile(0.90),
        "p99": hist.value_at_quantile(0.99),
        "max": hist.max(),
        "min": hist.min(),
    })
}
