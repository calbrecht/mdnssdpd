use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

pub const MDNS_PORT: u16 = 5353;
pub const MDNS_IPV4_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_IPV6_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const RECV_BUF_SIZE: usize = 65535;

/// A received mDNS packet with metadata.
#[derive(Clone)]
pub struct PacketEvent {
    pub data: Vec<u8>,
    pub source: SocketAddr,
    pub interface: String,
    pub timestamp: String,
}

pub fn list_interfaces() -> Result<()> {
    let ifaces = NetworkInterface::show().context("Failed to enumerate network interfaces")?;
    eprintln!("{:<20} {:<8} {}", "NAME", "INDEX", "ADDRESSES");
    eprintln!("{}", "-".repeat(60));
    for iface in &ifaces {
        let addrs: Vec<String> = iface.addr.iter().map(|a| format!("{}", a.ip())).collect();
        eprintln!("{:<20} {:<8} {}", iface.name, iface.index, addrs.join(", "));
    }
    Ok(())
}

pub fn resolve_interface_index(name: &str) -> Result<u32> {
    let ifaces = NetworkInterface::show().context("Failed to enumerate network interfaces")?;
    for iface in &ifaces {
        if iface.name == name {
            return Ok(iface.index);
        }
    }
    anyhow::bail!("Interface '{}' not found", name);
}

pub fn interface_ipv4_addr(name: &str) -> Option<Ipv4Addr> {
    let ifaces = NetworkInterface::show().ok()?;
    for iface in &ifaces {
        if iface.name == name {
            for addr in &iface.addr {
                if let std::net::IpAddr::V4(v4) = addr.ip() {
                    if !v4.is_loopback() {
                        return Some(v4);
                    }
                }
            }
        }
    }
    None
}

/// Collect all local IP addresses (for loop prevention).
pub fn local_addresses() -> Vec<std::net::IpAddr> {
    let ifaces = match NetworkInterface::show() {
        Ok(i) => i,
        Err(_) => return vec![],
    };
    let mut addrs = Vec::new();
    for iface in &ifaces {
        for addr in &iface.addr {
            addrs.push(addr.ip());
        }
    }
    addrs
}

pub fn create_mdns_v4_socket(iface_name: &str) -> Result<UdpSocket> {
    let if_index = resolve_interface_index(iface_name)?;
    let if_addr = interface_ipv4_addr(iface_name).unwrap_or(Ipv4Addr::UNSPECIFIED);

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create IPv4 socket")?;

    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(false)?;
    socket.set_multicast_loop_v4(true)?;
    socket.set_multicast_if_v4(&if_addr)?;

    // Bind to 0.0.0.0 for multicast reception — binding to a specific IP
    // causes the kernel to not deliver multicast packets (dst=224.0.0.251).
    // SO_BINDTODEVICE restricts reception to this interface only.
    #[cfg(target_os = "linux")]
    socket
        .bind_device(Some(iface_name.as_bytes()))
        .with_context(|| format!("Failed to SO_BINDTODEVICE on {}", iface_name))?;
    let bind_addr: SockAddr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into();
    socket
        .bind(&bind_addr)
        .with_context(|| format!("Failed to bind IPv4 socket on {}", iface_name))?;

    socket
        .join_multicast_v4_n(
            &MDNS_IPV4_ADDR,
            &socket2::InterfaceIndexOrAddress::Index(if_index),
        )
        .with_context(|| format!("Failed to join IPv4 multicast on {}", iface_name))?;

    Ok(socket.into())
}

pub fn create_mdns_v6_socket(iface_name: &str) -> Result<UdpSocket> {
    let if_index = resolve_interface_index(iface_name)?;

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create IPv6 socket")?;

    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(false)?;
    socket.set_only_v6(true)?;
    socket.set_multicast_loop_v6(true)?;
    socket.set_multicast_if_v6(if_index)?;

    let bind_addr: SockAddr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, MDNS_PORT)).into();
    socket.bind(&bind_addr).context("Failed to bind IPv6 socket")?;

    // Bind to device so we only receive traffic from this interface
    #[cfg(target_os = "linux")]
    socket
        .bind_device(Some(iface_name.as_bytes()))
        .with_context(|| format!("Failed to SO_BINDTODEVICE on {}", iface_name))?;

    socket
        .join_multicast_v6(&MDNS_IPV6_ADDR, if_index)
        .with_context(|| format!("Failed to join IPv6 multicast on {}", iface_name))?;

    Ok(socket.into())
}

/// Run a blocking receive loop, sending packets to the channel.
pub fn recv_loop(iface: String, socket: UdpSocket, tx: Sender<PacketEvent>) {
    let mut buf = vec![0u8; RECV_BUF_SIZE];
    eprintln!("[{}] Listening for mDNS traffic...", iface);

    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                let timestamp =
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
                let event = PacketEvent {
                    data: buf[..size].to_vec(),
                    source: src,
                    interface: iface.clone(),
                    timestamp,
                };
                if tx.send(event).is_err() {
                    eprintln!("[{}] Channel closed, stopping receiver", iface);
                    return;
                }
            }
            Err(e) => {
                eprintln!("[{}] recv error: {}", iface, e);
            }
        }
    }
}
