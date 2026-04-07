mod config;
mod dns_util;
mod filter;
mod output;
mod receiver;
mod route;
mod sender;
mod transform;

use std::collections::HashSet;
use std::net::IpAddr;
use std::thread;

use anyhow::Result;
use clap::Parser;
use crossbeam_channel::bounded;

use receiver::PacketEvent;
use route::Route;

#[derive(Parser)]
#[command(name = "dnssd-powertools", about = "DNS-SD/mDNS reflector and power tools")]
struct Cli {
    /// Path to TOML route configuration file
    #[arg(short, long)]
    config: String,

    /// Also join IPv6 multicast group (ff02::fb)
    #[arg(short = '6', long, default_value_t = false)]
    ipv6: bool,

    /// List available network interfaces and exit
    #[arg(short, long)]
    list: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.list {
        receiver::list_interfaces()?;
        return Ok(());
    }

    // Load config
    let cfg = config::Config::load(&cli.config)?;
    if cfg.route.is_empty() {
        anyhow::bail!("No routes defined in config");
    }

    eprintln!("dnssd-powertools starting ({} routes)", cfg.route.len());

    // Collect local addresses for loop prevention (only relevant if reflecting)
    let has_reflect = cfg.route.iter().any(|r| {
        r.output.iter().any(|o| matches!(o, config::OutputConfig::Reflect { .. }))
    });
    let local_addrs: HashSet<IpAddr> = if has_reflect {
        let addrs: HashSet<IpAddr> = receiver::local_addresses().into_iter().collect();
        eprintln!("Loop prevention active (local addrs: {})", addrs.len());
        addrs
    } else {
        HashSet::new()
    };

    // Build routes
    let mut routes: Vec<Route> = Vec::new();
    for route_cfg in &cfg.route {
        let r = Route::build(route_cfg)?;
        routes.push(r);
    }

    // Collect all input interfaces
    let input_ifaces = cfg.all_input_interfaces();
    if input_ifaces.is_empty() {
        anyhow::bail!("No input interfaces defined across routes");
    }

    // Create a channel for packet fan-out
    let (tx, rx) = bounded::<PacketEvent>(256);

    // Start receiver threads for each interface
    let mut recv_handles = Vec::new();
    for iface in &input_ifaces {
        // IPv4
        let iface_clone = iface.clone();
        let tx_clone = tx.clone();
        match receiver::create_mdns_v4_socket(&iface_clone) {
            Ok(sock) => {
                let label = format!("{}:v4", iface_clone);
                eprintln!("[{}] Joined mDNS IPv4 multicast", iface_clone);
                recv_handles.push(thread::spawn(move || {
                    receiver::recv_loop(label, sock, tx_clone);
                }));
            }
            Err(e) => eprintln!("[{}] Failed to set up IPv4: {:#}", iface, e),
        }

        // IPv6
        if cli.ipv6 {
            let iface_clone = iface.clone();
            let tx_clone = tx.clone();
            match receiver::create_mdns_v6_socket(&iface_clone) {
                Ok(sock) => {
                    let label = format!("{}:v6", iface_clone);
                    eprintln!("[{}] Joined mDNS IPv6 multicast", iface_clone);
                    recv_handles.push(thread::spawn(move || {
                        receiver::recv_loop(label, sock, tx_clone);
                    }));
                }
                Err(e) => eprintln!("[{}] Failed to set up IPv6: {:#}", iface, e),
            }
        }
    }

    // Drop the original sender so the channel closes when all receiver threads exit
    drop(tx);

    if recv_handles.is_empty() {
        anyhow::bail!("No receiver sockets could be created");
    }

    eprintln!("All receivers up. Processing packets...");

    // Main dispatch loop: receive packets and fan out to all routes
    for event in rx.iter() {
        // Loop prevention: skip packets from our own addresses
        if local_addrs.contains(&event.source.ip()) {
            continue;
        }

        for route in &routes {
            if let Err(e) = route.process(&event) {
                eprintln!("[route:{}] Error: {:#}", route.name, e);
            }
        }
    }

    // Wait for receiver threads (they run until the process exits)
    for h in recv_handles {
        let _ = h.join();
    }

    Ok(())
}
