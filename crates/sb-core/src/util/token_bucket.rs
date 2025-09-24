pub struct Bucket {
    cap: u64,
    tokens: f64,
    rate: f64,
    last: std::time::Instant,
}
impl Bucket {
    pub fn new(cap: u64, rate_per_s: f64) -> Self {
        Self {
            cap,
            tokens: cap as f64,
            rate: rate_per_s,
            last: std::time::Instant::now(),
        }
    }
    pub fn allow(&mut self, cost: u64) -> bool {
        let now = std::time::Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.cap as f64);
        if self.tokens >= cost as f64 {
            self.tokens -= cost as f64;
            true
        } else {
            false
        }
    }
}
