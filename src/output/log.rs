use anyhow::Result;

use crate::dns_util;
use super::{Output, OutputContext};

pub struct LogOutput {
    format: String,
}

impl LogOutput {
    pub fn new(format: &str) -> Self {
        Self {
            format: format.to_string(),
        }
    }

    /// Format the packet as a string (separated from I/O for testability).
    pub fn format_entry(&self, ctx: &OutputContext) -> Result<String> {
        let entry = dns_util::message_to_json(
            ctx.msg,
            &ctx.event.interface,
            &format!("{}", ctx.event.source),
            ctx.event.data.len(),
            &ctx.event.timestamp,
        );
        Ok(serde_json::to_string(&entry)?)
    }
}

impl Output for LogOutput {
    fn emit(&self, ctx: &OutputContext) -> Result<()> {
        let json = self.format_entry(ctx)?;
        println!("{}", json);
        Ok(())
    }

    fn name(&self) -> &str {
        "log"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receiver::PacketEvent;
    use hickory_proto::op::{Message, MessageType};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;

    fn make_test_context() -> (PacketEvent, Message, Vec<u8>) {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.set_authoritative(true);
        msg.add_answer(Record::from_rdata(
            Name::from_str("test.local.").unwrap(), 120,
            RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
        ));
        let wire = msg.to_vec().unwrap();
        let event = PacketEvent {
            data: wire.clone(),
            source: SocketAddr::from(([192, 168, 1, 1], 5353)),
            interface: "eth0:v4".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };
        (event, msg, wire)
    }

    #[test]
    fn test_log_output_new() {
        let log = LogOutput::new("json");
        assert_eq!(log.format, "json");
        assert_eq!(log.name(), "log");
    }

    #[test]
    fn test_format_entry_json() {
        let (event, msg, wire) = make_test_context();
        let log = LogOutput::new("json");
        let ctx = OutputContext { event: &event, msg: &msg, wire_bytes: &wire };
        let json_str = log.format_entry(&ctx).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["interface"], "eth0:v4");
        assert_eq!(parsed["source"], "192.168.1.1:5353");
        assert_eq!(parsed["message"]["message_type"], "response");
        assert_eq!(parsed["message"]["authoritative"], true);
        assert_eq!(parsed["message"]["answers"][0]["record_type"], "A");
        assert_eq!(parsed["message"]["answers"][0]["rdata"], "10.0.0.1");
    }

    #[test]
    fn test_format_entry_unknown_format_still_works() {
        let (event, msg, wire) = make_test_context();
        let log = LogOutput::new("unknown_format");
        let ctx = OutputContext { event: &event, msg: &msg, wire_bytes: &wire };
        // Should still produce valid JSON (fallback)
        let json_str = log.format_entry(&ctx).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["timestamp"].is_string());
    }

    #[test]
    fn test_format_entry_contains_all_fields() {
        let (event, msg, wire) = make_test_context();
        let log = LogOutput::new("json");
        let ctx = OutputContext { event: &event, msg: &msg, wire_bytes: &wire };
        let json_str = log.format_entry(&ctx).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert!(parsed["timestamp"].is_string());
        assert!(parsed["interface"].is_string());
        assert!(parsed["source"].is_string());
        assert!(parsed["packet_size"].is_number());
        assert!(parsed["message"].is_object());
        assert!(parsed["message"]["questions"].is_array());
        assert!(parsed["message"]["answers"].is_array());
        assert!(parsed["message"]["authorities"].is_array());
        assert!(parsed["message"]["additionals"].is_array());
    }

    #[test]
    fn test_emit_does_not_error() {
        let (event, msg, wire) = make_test_context();
        let log = LogOutput::new("json");
        let ctx = OutputContext { event: &event, msg: &msg, wire_bytes: &wire };
        // emit() prints to stdout — just verify it doesn't error
        assert!(log.emit(&ctx).is_ok());
    }
}
