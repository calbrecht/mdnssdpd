use std::collections::HashSet;

use anyhow::Result;
use crate::config::{RouteConfig, RouteFilterConfig};
use crate::dns_util;
use crate::filter::{self, FilterConfig, FilterEngine};
use crate::output::{self, Output, OutputContext};
use crate::receiver::PacketEvent;
use crate::transform::{self, TransformChain};

/// A compiled route: input filter → transform → outputs.
pub struct Route {
    pub name: String,
    pub input_interfaces: HashSet<String>,
    filter: Option<FilterEngine>,
    transforms: TransformChain,
    outputs: Vec<Box<dyn Output>>,
}

impl Route {
    pub fn build(config: &RouteConfig) -> Result<Self> {
        let input_interfaces: HashSet<String> = config.input.iter().cloned().collect();

        // Build filter engine from route filter config
        let filter = match &config.filter {
            Some(fc) => build_route_filter(fc)?,
            None => None,
        };

        // Build transform chain
        let transforms = transform::build_chain(&config.transform)?;

        // Build outputs
        let outputs = output::build_outputs(&config.output)?;

        eprintln!(
            "[route:{}] input={:?} transforms={} outputs={}",
            config.name,
            config.input,
            config.transform.len(),
            outputs.len(),
        );

        Ok(Self {
            name: config.name.clone(),
            input_interfaces,
            filter,
            transforms,
            outputs,
        })
    }

    /// Process a received packet through this route's pipeline.
    pub fn process(&self, event: &PacketEvent) -> Result<()> {
        // Check if this packet is from one of our input interfaces
        // Match on base interface name (strip :v4/:v6 suffix)
        let base_iface = event.interface.split(':').next().unwrap_or(&event.interface);
        if !self.input_interfaces.contains(base_iface) && !self.input_interfaces.contains(&event.interface) {
            return Ok(());
        }

        // Parse
        let mut msg = match dns_util::parse_message(&event.data) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[route:{}] Parse error from {}: {}", self.name, event.source, e);
                return Ok(());
            }
        };

        // Filter (on JSON representation)
        if let Some(filter) = &self.filter {
            let json_entry = serde_json::to_value(&dns_util::message_to_json(
                &msg,
                &event.interface,
                &format!("{}", event.source),
                event.data.len(),
                &event.timestamp,
            ))?;
            if !filter.should_print(&json_entry) {
                return Ok(());
            }
        }

        // Transform (on Message, in-place)
        if !self.transforms.apply(&mut msg)? {
            return Ok(()); // transform dropped the packet
        }

        // Drop empty packets — transforms may have stripped all content
        if !self.transforms.is_empty()
            && msg.queries().is_empty()
            && msg.answers().is_empty()
            && msg.name_servers().is_empty()
            && msg.additionals().is_empty()
        {
            return Ok(());
        }

        // Re-serialize for reflect outputs
        let wire_bytes = if self.transforms.is_empty() {
            // No transforms — use original bytes (faster, preserves wire format exactly)
            event.data.clone()
        } else {
            msg.to_vec()?
        };

        // Output
        let ctx = OutputContext {
            event,
            msg: &msg,
            wire_bytes: &wire_bytes,
        };

        for output in &self.outputs {
            if let Err(e) = output.emit(&ctx) {
                eprintln!("[route:{}] Output {} error: {}", self.name, output.name(), e);
            }
        }

        Ok(())
    }
}

/// Convert RouteFilterConfig into what FilterEngine::build expects.
/// Build a route directly from components (for testing without network sockets).
#[cfg(test)]
pub fn build_test_route(
    name: &str,
    input_interfaces: Vec<String>,
    filter: Option<FilterEngine>,
    transforms: TransformChain,
    outputs: Vec<Box<dyn Output>>,
) -> Route {
    Route {
        name: name.to_string(),
        input_interfaces: input_interfaces.into_iter().collect(),
        filter,
        transforms,
        outputs,
    }
}

fn build_route_filter(rfc: &RouteFilterConfig) -> Result<Option<FilterEngine>> {
    // Load chain files
    let chain_configs = filter::load_configs(&rfc.chain)?;

    // Convert inline rules to a FilterConfig
    let inline_config = FilterConfig {
        chain: vec![],
        mode: rfc.mode.clone(),
        action: rfc.action.clone(),
        rule: rfc
            .rule
            .iter()
            .map(|r| filter::Rule {
                negate: r.negate,
                condition: r
                    .condition
                    .iter()
                    .map(|c| filter::Condition {
                        path: c.path.clone(),
                        op: c.op.clone(),
                        value: c.value.clone(),
                    })
                    .collect(),
            })
            .collect(),
    };

    // Merge: chain configs first, then inline config (if it has rules)
    let mut all_configs = chain_configs;
    if !inline_config.rule.is_empty() {
        all_configs.push(inline_config);
    }

    FilterEngine::build(all_configs, &rfc.jq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::OutputContext;
    use crate::receiver::PacketEvent;
    use crate::transform::{self, TransformChain};
    use hickory_proto::op::{Message, MessageType};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData, Record};
    use hickory_proto::serialize::binary::BinDecodable;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    /// A test output that captures emitted wire bytes.
    struct CaptureOutput {
        captured: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl CaptureOutput {
        fn new() -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let captured = Arc::new(Mutex::new(Vec::new()));
            (Self { captured: captured.clone() }, captured)
        }
    }

    impl Output for CaptureOutput {
        fn emit(&self, ctx: &OutputContext) -> Result<()> {
            self.captured.lock().unwrap().push(ctx.wire_bytes.to_vec());
            Ok(())
        }
        fn name(&self) -> &str { "capture" }
    }

    fn make_query_event(iface: &str, name: &str) -> PacketEvent {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query);
        let mut query = hickory_proto::op::Query::new();
        query.set_name(Name::from_str(name).unwrap());
        query.set_query_type(hickory_proto::rr::RecordType::PTR);
        msg.add_query(query);
        let data = msg.to_vec().unwrap();
        PacketEvent {
            data,
            source: SocketAddr::from(([192, 168, 1, 100], 5353)),
            interface: iface.to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    fn make_response_event(iface: &str) -> PacketEvent {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.set_authoritative(true);
        msg.add_answer(Record::from_rdata(
            Name::from_str("_tidal._tcp.local.").unwrap(), 4500,
            RData::PTR(hickory_proto::rr::rdata::PTR(
                Name::from_str("streamer._tidal._tcp.local.").unwrap(),
            )),
        ));
        msg.add_additional(Record::from_rdata(
            Name::from_str("streamer.local.").unwrap(), 120,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 50))),
        ));
        msg.add_additional(Record::from_rdata(
            Name::from_str("streamer.local.").unwrap(), 120,
            RData::AAAA(AAAA("fe80::1".parse().unwrap())),
        ));
        let data = msg.to_vec().unwrap();
        PacketEvent {
            data,
            source: SocketAddr::from(([192, 168, 1, 50], 5353)),
            interface: iface.to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    // --- Interface matching ---

    #[test]
    fn test_route_ignores_wrong_interface() {
        let (output, captured) = CaptureOutput::new();
        let route = build_test_route(
            "test", vec!["eth0".into()],
            None, TransformChain::new(vec![]),
            vec![Box::new(output)],
        );
        let event = make_query_event("eth1:v4", "_test._tcp.local.");
        route.process(&event).unwrap();
        assert!(captured.lock().unwrap().is_empty());
    }

    #[test]
    fn test_route_matches_base_interface() {
        let (output, captured) = CaptureOutput::new();
        let route = build_test_route(
            "test", vec!["eth0".into()],
            None, TransformChain::new(vec![]),
            vec![Box::new(output)],
        );
        let event = make_query_event("eth0:v4", "_test._tcp.local.");
        route.process(&event).unwrap();
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_route_matches_full_interface_name() {
        let (output, captured) = CaptureOutput::new();
        let route = build_test_route(
            "test", vec!["eth0:v4".into()],
            None, TransformChain::new(vec![]),
            vec![Box::new(output)],
        );
        let event = make_query_event("eth0:v4", "_test._tcp.local.");
        route.process(&event).unwrap();
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    // --- Pass-through (no filter, no transform) ---

    #[test]
    fn test_route_passthrough() {
        let (output, captured) = CaptureOutput::new();
        let route = build_test_route(
            "test", vec!["eth0".into()],
            None, TransformChain::new(vec![]),
            vec![Box::new(output)],
        );
        let event = make_query_event("eth0:v4", "_test._tcp.local.");
        route.process(&event).unwrap();

        let results = captured.lock().unwrap();
        assert_eq!(results.len(), 1);
        // No transforms → original bytes forwarded
        assert_eq!(results[0], event.data);
    }

    // --- Filter rejection ---

    fn eq_filter(path: &str, value: &str) -> Option<FilterEngine> {
        use crate::filter::{FilterConfig, Rule, Condition};
        FilterEngine::build(
            vec![FilterConfig {
                mode: "any".into(),
                action: "show".into(),
                rule: vec![Rule {
                    negate: false,
                    condition: vec![Condition {
                        path: path.into(),
                        op: crate::filter::ops::Op::Eq,
                        value: serde_json::json!(value),
                    }],
                }],
                chain: vec![],
            }],
            &[],
        ).unwrap()
    }

    #[test]
    fn test_route_filter_rejects() {
        let (output, captured) = CaptureOutput::new();
        let filter = eq_filter("message.message_type", "response");
        let route = build_test_route(
            "test", vec!["eth0".into()],
            filter, TransformChain::new(vec![]),
            vec![Box::new(output)],
        );
        // Send a query — filter wants responses only
        let event = make_query_event("eth0:v4", "_test._tcp.local.");
        route.process(&event).unwrap();
        assert!(captured.lock().unwrap().is_empty());
    }

    #[test]
    fn test_route_filter_passes() {
        let (output, captured) = CaptureOutput::new();
        let filter = eq_filter("message.message_type", "query");
        let route = build_test_route(
            "test", vec!["eth0".into()],
            filter, TransformChain::new(vec![]),
            vec![Box::new(output)],
        );
        let event = make_query_event("eth0:v4", "_test._tcp.local.");
        route.process(&event).unwrap();
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    // --- Transform: fe80 stripping ---

    #[test]
    fn test_route_strips_link_local() {
        let (output, captured) = CaptureOutput::new();
        let transforms = transform::build_chain(&[
            crate::config::TransformConfig::RemoveRecords {
                section: "all".into(),
                record_type: Some("AAAA".into()),
                match_name: None,
                match_rdata: Some("fe80".into()),
            },
        ]).unwrap();

        let route = build_test_route(
            "test", vec!["eth0".into()],
            None, transforms,
            vec![Box::new(output)],
        );

        let event = make_response_event("eth0:v4");
        route.process(&event).unwrap();

        let results = captured.lock().unwrap();
        assert_eq!(results.len(), 1);

        // Parse the output and verify fe80 is gone
        let out_msg = Message::from_bytes(&results[0]).unwrap();
        assert_eq!(out_msg.answers().len(), 1); // PTR preserved
        // Additionals: A preserved, fe80 AAAA stripped
        for record in out_msg.additionals() {
            if record.record_type() == hickory_proto::rr::RecordType::AAAA {
                let rdata = format!("{}", record.data());
                assert!(!rdata.starts_with("fe80"), "fe80 should be stripped, got: {rdata}");
            }
        }
    }

    // --- Transform: empty packet dropped ---

    #[test]
    fn test_route_drops_empty_packet_after_transform() {
        let (output, captured) = CaptureOutput::new();
        let transforms = transform::build_chain(&[
            crate::config::TransformConfig::RemoveServices {
                match_name: "_test".into(),
            },
        ]).unwrap();

        let route = build_test_route(
            "test", vec!["eth0".into()],
            None, transforms,
            vec![Box::new(output)],
        );

        // Query with only _test question → stripped → empty → dropped
        let event = make_query_event("eth0:v4", "_test._tcp.local.");
        route.process(&event).unwrap();
        assert!(captured.lock().unwrap().is_empty());
    }

    #[test]
    fn test_route_keeps_nonempty_after_partial_strip() {
        let (output, captured) = CaptureOutput::new();
        let transforms = transform::build_chain(&[
            crate::config::TransformConfig::RemoveServices {
                match_name: "_google".into(),
            },
        ]).unwrap();

        let route = build_test_route(
            "test", vec!["eth0".into()],
            None, transforms,
            vec![Box::new(output)],
        );

        // Build a packet with two questions: _google (stripped) and _tidal (kept)
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query);
        let mut q1 = hickory_proto::op::Query::new();
        q1.set_name(Name::from_str("_googlecast._tcp.local.").unwrap());
        q1.set_query_type(hickory_proto::rr::RecordType::PTR);
        msg.add_query(q1);
        let mut q2 = hickory_proto::op::Query::new();
        q2.set_name(Name::from_str("_tidalconnect._tcp.local.").unwrap());
        q2.set_query_type(hickory_proto::rr::RecordType::PTR);
        msg.add_query(q2);

        let event = PacketEvent {
            data: msg.to_vec().unwrap(),
            source: SocketAddr::from(([192, 168, 1, 100], 5353)),
            interface: "eth0:v4".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        route.process(&event).unwrap();

        let results = captured.lock().unwrap();
        assert_eq!(results.len(), 1);
        let out_msg = Message::from_bytes(&results[0]).unwrap();
        assert_eq!(out_msg.queries().len(), 1);
        assert_eq!(out_msg.queries()[0].name().to_string(), "_tidalconnect._tcp.local.");
    }

    // --- Invalid packet ---

    #[test]
    fn test_route_handles_invalid_packet() {
        let (output, captured) = CaptureOutput::new();
        let route = build_test_route(
            "test", vec!["eth0".into()],
            None, TransformChain::new(vec![]),
            vec![Box::new(output)],
        );
        let event = PacketEvent {
            data: vec![0xFF, 0xFF], // garbage
            source: SocketAddr::from(([10, 0, 0, 1], 5353)),
            interface: "eth0:v4".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };
        // Should not panic, just skip
        route.process(&event).unwrap();
        assert!(captured.lock().unwrap().is_empty());
    }

    // --- Multiple outputs ---

    #[test]
    fn test_route_emits_to_all_outputs() {
        let (out1, cap1) = CaptureOutput::new();
        let (out2, cap2) = CaptureOutput::new();
        let route = build_test_route(
            "test", vec!["eth0".into()],
            None, TransformChain::new(vec![]),
            vec![Box::new(out1), Box::new(out2)],
        );
        let event = make_query_event("eth0:v4", "_test._tcp.local.");
        route.process(&event).unwrap();
        assert_eq!(cap1.lock().unwrap().len(), 1);
        assert_eq!(cap2.lock().unwrap().len(), 1);
    }

    // --- Route::build with config (log-only, no network) ---

    #[test]
    fn test_route_build_log_only() {
        use crate::config::{RouteConfig, OutputConfig};
        let config = RouteConfig {
            name: "test".into(),
            input: vec!["eth0".into()],
            filter: None,
            transform: vec![],
            output: vec![OutputConfig::Log {}],
        };
        let route = Route::build(&config).unwrap();
        assert_eq!(route.name, "test");
        assert!(route.input_interfaces.contains("eth0"));
    }

    // --- build_route_filter ---

    #[test]
    fn test_build_route_filter_with_rules() {
        use crate::config::{RouteFilterConfig, RouteFilterRule, RouteFilterCondition};
        use crate::filter::ops::Op;
        let rfc = RouteFilterConfig {
            chain: vec![],
            mode: "any".into(),
            action: "show".into(),
            jq: vec![],
            rule: vec![RouteFilterRule {
                negate: false,
                condition: vec![RouteFilterCondition {
                    path: "message.message_type".into(),
                    op: Op::Eq,
                    value: serde_json::json!("response"),
                }],
            }],
        };
        let filter = build_route_filter(&rfc).unwrap();
        assert!(filter.is_some());
    }

    #[test]
    fn test_build_route_filter_empty() {
        use crate::config::RouteFilterConfig;
        let rfc = RouteFilterConfig {
            chain: vec![],
            mode: "any".into(),
            action: "show".into(),
            jq: vec![],
            rule: vec![],
        };
        let filter = build_route_filter(&rfc).unwrap();
        assert!(filter.is_none());
    }
}
