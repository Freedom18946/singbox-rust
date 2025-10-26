use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn bench_connect_loopback(c: &mut Criterion) {
    // Set up a local listener on a random port
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(_) => return,
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(_) => return,
    };

    // Spawn a simple echo server
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            // Simple echo server - just close the connection
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });

    // Small delay to let the server start
    thread::sleep(Duration::from_millis(10));

    c.bench_function("connect_loopback", |b| {
        b.iter(|| {
            // Benchmark the connect operation
            let result = TcpStream::connect(addr);
            let _ = black_box(result);
        })
    });
}

criterion_group!(benches, bench_connect_loopback);
criterion_main!(benches);
#[cfg(not(feature = "bench"))]
fn main() {}
