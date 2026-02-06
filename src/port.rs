use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpListener;

/// Attempt to find a free port in the range [from, up_to] inclusive.
pub async fn find_port(addr: IpAddr, from: u16, up_to: u16) -> Option<u16> {
    for port in from..=up_to {
        let socket = SocketAddr::new(addr, port);
        if TcpListener::bind(socket).await.is_ok() {
            return Some(port);
        }
    }
    None
}
