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
#[command(name = "mdnssdpd", about = "DNS-SD/mDNS reflector and power tools")]
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

/// Check if any route has a reflect output (for loop prevention).
fn has_reflect_output(cfg: &config::Config) -> bool {
    cfg.route.iter().any(|r| {
        r.output.iter().any(|o| matches!(o, config::OutputConfig::Reflect { .. }))
    })
}

/// Dispatch a single packet event to all routes, with loop prevention.
fn dispatch_event(
    event: &PacketEvent,
    routes: &[Route],
    local_addrs: &HashSet<IpAddr>,
) {
    // Loop prevention: skip packets from our own addresses
    if local_addrs.contains(&event.source.ip()) {
        return;
    }

    for route in routes {
        if let Err(e) = route.process(event) {
            eprintln!("[route:{}] Error: {:#}", route.name, e);
        }
    }
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

    eprintln!("mdnssdpd starting ({} routes)", cfg.route.len());

    // Collect local addresses for loop prevention (only relevant if reflecting)
    let local_addrs: HashSet<IpAddr> = if has_reflect_output(&cfg) {
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

    // Main dispatch loop
    for event in rx.iter() {
        dispatch_event(&event, &routes, &local_addrs);
    }

    // Wait for receiver threads (they run until the process exits)
    for h in recv_handles {
        let _ = h.join();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, OutputConfig, RouteConfig};
    use crate::receiver::PacketEvent;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    fn make_test_config(outputs: Vec<OutputConfig>) -> Config {
        Config {
            route: vec![RouteConfig {
                name: "test".into(),
                input: vec!["eth0".into()],
                filter: None,
                transform: vec![],
                output: outputs,
            }],
        }
    }

    #[test]
    fn test_has_reflect_output_true() {
        let cfg = make_test_config(vec![
            OutputConfig::Reflect { interfaces: vec!["eth1".into()] },
        ]);
        assert!(has_reflect_output(&cfg));
    }

    #[test]
    fn test_has_reflect_output_false() {
        let cfg = make_test_config(vec![
            OutputConfig::Log {},
        ]);
        assert!(!has_reflect_output(&cfg));
    }

    #[test]
    fn test_has_reflect_output_mixed() {
        let cfg = make_test_config(vec![
            OutputConfig::Log {},
            OutputConfig::Reflect { interfaces: vec!["eth1".into()] },
        ]);
        assert!(has_reflect_output(&cfg));
    }

    #[test]
    fn test_has_reflect_output_no_routes() {
        let cfg = Config { route: vec![] };
        assert!(!has_reflect_output(&cfg));
    }

    // --- dispatch_event ---

    fn make_event(source_ip: [u8; 4]) -> PacketEvent {
        use hickory_proto::op::Message;
        let msg = Message::new();
        PacketEvent {
            data: msg.to_vec().unwrap(),
            source: SocketAddr::from((source_ip, 5353)),
            interface: "eth0:v4".into(),
            timestamp: "2024-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn test_dispatch_skips_local_address() {
        let mut local = HashSet::new();
        local.insert(IpAddr::from([192, 168, 1, 1]));

        // Build a route with a CaptureOutput
        let captured = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let cap = captured.clone();

        struct TestOutput(Arc<Mutex<Vec<Vec<u8>>>>);
        impl crate::output::Output for TestOutput {
            fn emit(&self, ctx: &crate::output::OutputContext) -> Result<()> {
                self.0.lock().unwrap().push(ctx.wire_bytes.to_vec());
                Ok(())
            }
            fn name(&self) -> &str { "test" }
        }

        let route = crate::route::build_test_route(
            "test", vec!["eth0".into()],
            None, crate::transform::TransformChain::new(vec![]),
            vec![Box::new(TestOutput(cap))],
        );

        // Event from local address → should be skipped
        let event = make_event([192, 168, 1, 1]);
        dispatch_event(&event, &[route], &local);
        assert!(captured.lock().unwrap().is_empty());
    }

    #[test]
    fn test_dispatch_passes_non_local() {
        let local = HashSet::new(); // no loop prevention

        let captured = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let cap = captured.clone();

        struct TestOutput(Arc<Mutex<Vec<Vec<u8>>>>);
        impl crate::output::Output for TestOutput {
            fn emit(&self, ctx: &crate::output::OutputContext) -> Result<()> {
                self.0.lock().unwrap().push(ctx.wire_bytes.to_vec());
                Ok(())
            }
            fn name(&self) -> &str { "test" }
        }

        let route = crate::route::build_test_route(
            "test", vec!["eth0".into()],
            None, crate::transform::TransformChain::new(vec![]),
            vec![Box::new(TestOutput(cap))],
        );

        let event = make_event([10, 0, 0, 1]);
        dispatch_event(&event, &[route], &local);
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_dispatch_to_multiple_routes() {
        let local = HashSet::new();

        let cap1 = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let cap2 = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let c1 = cap1.clone();
        let c2 = cap2.clone();

        struct TestOutput(Arc<Mutex<Vec<Vec<u8>>>>);
        impl crate::output::Output for TestOutput {
            fn emit(&self, ctx: &crate::output::OutputContext) -> Result<()> {
                self.0.lock().unwrap().push(ctx.wire_bytes.to_vec());
                Ok(())
            }
            fn name(&self) -> &str { "test" }
        }

        let r1 = crate::route::build_test_route(
            "r1", vec!["eth0".into()],
            None, crate::transform::TransformChain::new(vec![]),
            vec![Box::new(TestOutput(c1))],
        );
        let r2 = crate::route::build_test_route(
            "r2", vec!["eth0".into()],
            None, crate::transform::TransformChain::new(vec![]),
            vec![Box::new(TestOutput(c2))],
        );

        let event = make_event([10, 0, 0, 1]);
        dispatch_event(&event, &[r1, r2], &local);
        assert_eq!(cap1.lock().unwrap().len(), 1);
        assert_eq!(cap2.lock().unwrap().len(), 1);
    }
}
