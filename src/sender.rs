use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::receiver::{interface_ipv4_addr, MDNS_IPV4_ADDR, MDNS_PORT};

/// Sends mDNS multicast packets on a specific interface.
pub struct MdnsSender {
    socket: UdpSocket,
    dest: SocketAddr,
    pub iface_name: String,
}

impl MdnsSender {
    pub fn new_v4(iface_name: &str) -> Result<Self> {
        let if_addr = interface_ipv4_addr(iface_name)
            .unwrap_or(Ipv4Addr::UNSPECIFIED);

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .context("Failed to create send socket")?;

        socket.set_reuse_address(true)?;
        #[cfg(not(target_os = "windows"))]
        socket.set_reuse_port(true)?;
        socket.set_multicast_if_v4(&if_addr)?;
        socket.set_multicast_ttl_v4(255)?;
        // Don't receive our own reflected packets
        socket.set_multicast_loop_v4(false)?;

        let bind_addr: SockAddr = SocketAddr::from((if_addr, 0)).into();
        socket.bind(&bind_addr).context("Failed to bind send socket")?;

        Ok(Self {
            socket: socket.into(),
            dest: SocketAddr::from((MDNS_IPV4_ADDR, MDNS_PORT)),
            iface_name: iface_name.to_string(),
        })
    }

    pub fn send(&self, data: &[u8]) -> Result<usize> {
        self.socket
            .send_to(data, self.dest)
            .with_context(|| format!("Failed to send on {}", self.iface_name))
    }
}
