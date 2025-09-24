#[derive(Clone, Debug)]
pub enum Address {
    Ip(std::net::SocketAddr),
    Domain(String, u16),
}
