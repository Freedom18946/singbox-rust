use std::env;
use std::time::Instant;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let host = env::args().nth(1).unwrap_or_else(|| "example.com".into());
    let port: u16 = env::args().nth(2).unwrap_or_else(|| "80".into()).parse().unwrap_or(80);

    let t0 = Instant::now();
    let v = sb_core::dns::resolve::resolve_all(&host, port).await?;
    let dt = t0.elapsed().as_millis();

    println!("resolved {}:{} -> {:?} ({} ms)", host, port, v, dt);
    Ok(())
}