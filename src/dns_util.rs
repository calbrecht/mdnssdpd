use anyhow::{Context, Result};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinDecodable;
use serde::Serialize;
use serde_json::json;

// --- JSON output types ---

#[derive(Serialize, Clone, Debug)]
pub struct MdnsLogEntry {
    pub timestamp: String,
    pub interface: String,
    pub source: String,
    pub packet_size: usize,
    pub message: DnsMessageInfo,
}

#[derive(Serialize, Clone, Debug)]
pub struct DnsMessageInfo {
    pub id: u16,
    pub message_type: String,
    pub opcode: String,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: String,
    pub question_count: usize,
    pub answer_count: usize,
    pub authority_count: usize,
    pub additional_count: usize,
    pub questions: Vec<QuestionInfo>,
    pub answers: Vec<RecordInfo>,
    pub authorities: Vec<RecordInfo>,
    pub additionals: Vec<RecordInfo>,
}

#[derive(Serialize, Clone, Debug)]
pub struct QuestionInfo {
    pub name: String,
    pub record_type: String,
    pub class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefer_unicast: Option<bool>,
}

#[derive(Serialize, Clone, Debug)]
pub struct RecordInfo {
    pub name: String,
    pub record_type: String,
    pub class: String,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_flush: Option<bool>,
    pub rdata: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdata_detail: Option<serde_json::Value>,
}

// --- Parsing ---

pub fn parse_message(buf: &[u8]) -> Result<Message> {
    Message::from_bytes(buf).context("Failed to parse DNS message")
}

pub fn message_to_json(msg: &Message, iface: &str, source: &str, packet_size: usize, timestamp: &str) -> MdnsLogEntry {
    let header = msg.header();

    let questions: Vec<QuestionInfo> = msg
        .queries()
        .iter()
        .map(|q| {
            let raw_class: u16 = q.query_class().into();
            let prefer_unicast = if raw_class & 0x8000 != 0 {
                Some(true)
            } else {
                None
            };
            let actual_class: hickory_proto::rr::DNSClass = (raw_class & 0x7FFF).into();
            QuestionInfo {
                name: format!("{}", q.name()),
                record_type: format!("{}", q.query_type()),
                class: format!("{}", actual_class),
                prefer_unicast,
            }
        })
        .collect();

    let answers: Vec<RecordInfo> = msg.answers().iter().map(record_to_info).collect();
    let authorities: Vec<RecordInfo> = msg.name_servers().iter().map(record_to_info).collect();
    let additionals: Vec<RecordInfo> = msg.additionals().iter().map(record_to_info).collect();

    let message = DnsMessageInfo {
        id: header.id(),
        message_type: if header.message_type() == hickory_proto::op::MessageType::Query {
            "query".into()
        } else {
            "response".into()
        },
        opcode: format!("{}", header.op_code()),
        authoritative: header.authoritative(),
        truncated: header.truncated(),
        recursion_desired: header.recursion_desired(),
        recursion_available: header.recursion_available(),
        response_code: format!("{}", header.response_code()),
        question_count: header.query_count() as usize,
        answer_count: header.answer_count() as usize,
        authority_count: header.name_server_count() as usize,
        additional_count: header.additional_count() as usize,
        questions,
        answers,
        authorities,
        additionals,
    };

    MdnsLogEntry {
        timestamp: timestamp.to_string(),
        interface: iface.to_string(),
        source: source.to_string(),
        packet_size,
        message,
    }
}

fn parse_rdata_detail(rdata: &RData) -> (String, Option<serde_json::Value>) {
    match rdata {
        RData::A(a) => (format!("{}", a.0), None),
        RData::AAAA(aaaa) => (format!("{}", aaaa.0), None),
        RData::PTR(ptr) => (format!("{}", ptr.0), None),
        RData::SRV(srv) => {
            let detail = json!({
                "priority": srv.priority(),
                "weight": srv.weight(),
                "port": srv.port(),
                "target": format!("{}", srv.target()),
            });
            (format!("{}:{} -> {}", srv.target(), srv.port(), srv.priority()), Some(detail))
        }
        RData::TXT(txt) => {
            let texts: Vec<String> = txt
                .iter()
                .map(|t| String::from_utf8_lossy(t).into_owned())
                .collect();
            let detail = json!({ "entries": texts });
            (texts.join("; "), Some(detail))
        }
        RData::CNAME(cname) => (format!("{}", cname.0), None),
        RData::MX(mx) => {
            let detail = json!({
                "preference": mx.preference(),
                "exchange": format!("{}", mx.exchange()),
            });
            (format!("{} {}", mx.preference(), mx.exchange()), Some(detail))
        }
        RData::NS(ns) => (format!("{}", ns.0), None),
        RData::OPT(_) => {
            let detail = json!({ "type": "OPT" });
            ("OPT".into(), Some(detail))
        }
        other => (format!("{:?}", other), None),
    }
}

fn record_to_info(record: &Record) -> RecordInfo {
    let (rdata, rdata_detail) = parse_rdata_detail(record.data());

    let raw_class: u16 = record.dns_class().into();
    let cache_flush = if raw_class & 0x8000 != 0 {
        Some(true)
    } else {
        None
    };

    // Mask off cache-flush bit to get the actual DNS class
    let actual_class: hickory_proto::rr::DNSClass = (raw_class & 0x7FFF).into();

    RecordInfo {
        name: format!("{}", record.name()),
        record_type: format!("{}", record.record_type()),
        class: format!("{}", actual_class),
        ttl: record.ttl(),
        cache_flush,
        rdata,
        rdata_detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_proto::rr::rdata::{A, AAAA, SRV};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    /// Build a response Message with cache-flush records, mimicking real mDNS traffic.
    fn make_mdns_response_with_cache_flush() -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.set_authoritative(true);

        // PTR record — normal class IN (no cache-flush on PTR per RFC 6762)
        let ptr = Record::from_rdata(
            Name::from_str("_smb._tcp.local.").unwrap(),
            4500,
            RData::PTR(hickory_proto::rr::rdata::PTR(
                Name::from_str("myhost._smb._tcp.local.").unwrap(),
            )),
        );
        msg.add_answer(ptr);

        // SRV record — cache-flush set (class IN | 0x8000 = 0x8001)
        let mut srv = Record::from_rdata(
            Name::from_str("myhost._smb._tcp.local.").unwrap(),
            120,
            RData::SRV(SRV::new(0, 0, 445, Name::from_str("myhost.local.").unwrap())),
        );
        srv.set_dns_class(DNSClass::from(0x8001u16));
        msg.add_answer(srv);

        // A record — cache-flush set
        let mut a = Record::from_rdata(
            Name::from_str("myhost.local.").unwrap(),
            120,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 100))),
        );
        a.set_dns_class(DNSClass::from(0x8001u16));
        msg.add_answer(a);

        // AAAA record — cache-flush set, link-local
        let mut aaaa = Record::from_rdata(
            Name::from_str("myhost.local.").unwrap(),
            120,
            RData::AAAA(AAAA("fe80::1".parse().unwrap())),
        );
        aaaa.set_dns_class(DNSClass::from(0x8001u16));
        msg.add_answer(aaaa);

        // AAAA record — cache-flush set, global
        let mut aaaa_global = Record::from_rdata(
            Name::from_str("myhost.local.").unwrap(),
            120,
            RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
        );
        aaaa_global.set_dns_class(DNSClass::from(0x8001u16));
        msg.add_answer(aaaa_global);

        msg
    }

    #[test]
    fn test_cache_flush_class_not_unknown() {
        let msg = make_mdns_response_with_cache_flush();
        let entry = message_to_json(&msg, "eth0:v4", "10.0.0.1:5353", 200, "2024-01-01T00:00:00Z");

        // PTR: normal IN, no cache-flush
        assert_eq!(entry.message.answers[0].class, "IN");
        assert_eq!(entry.message.answers[0].cache_flush, None);

        // SRV: IN with cache-flush
        assert_eq!(entry.message.answers[1].class, "IN");
        assert_eq!(entry.message.answers[1].cache_flush, Some(true));

        // A: IN with cache-flush
        assert_eq!(entry.message.answers[2].class, "IN");
        assert_eq!(entry.message.answers[2].cache_flush, Some(true));

        // AAAA link-local: IN with cache-flush
        assert_eq!(entry.message.answers[3].class, "IN");
        assert_eq!(entry.message.answers[3].cache_flush, Some(true));

        // AAAA global: IN with cache-flush
        assert_eq!(entry.message.answers[4].class, "IN");
        assert_eq!(entry.message.answers[4].cache_flush, Some(true));
    }

    #[test]
    fn test_cache_flush_class_not_unknown_after_roundtrip() {
        // Simulate what happens with a wire-format packet: serialize then parse
        let msg = make_mdns_response_with_cache_flush();
        let wire = msg.to_vec().unwrap();
        let parsed = parse_message(&wire).unwrap();

        let entry = message_to_json(&parsed, "eth0:v4", "10.0.0.1:5353", wire.len(), "2024-01-01T00:00:00Z");

        // All records must show class "IN", not "UNKNOWN"
        for (i, answer) in entry.message.answers.iter().enumerate() {
            assert_eq!(
                answer.class, "IN",
                "Answer {} ({} {}) has class '{}' instead of 'IN'",
                i, answer.name, answer.record_type, answer.class
            );
        }

        // Cache-flush records (SRV, A, AAAA) must have cache_flush = Some(true)
        assert_eq!(entry.message.answers[0].cache_flush, None); // PTR
        for answer in &entry.message.answers[1..] {
            assert_eq!(
                answer.cache_flush,
                Some(true),
                "Record {} {} missing cache_flush flag",
                answer.name, answer.record_type
            );
        }
    }

    #[test]
    fn test_question_class_with_qu_bit() {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query);

        // Question with QU bit set (unicast-response requested)
        let mut query = Query::new();
        query.set_name(Name::from_str("_smb._tcp.local.").unwrap());
        query.set_query_type(RecordType::PTR);
        query.set_query_class(DNSClass::from(0x8001u16)); // IN + QU bit
        msg.add_query(query);

        // Normal question without QU bit
        let mut query2 = Query::new();
        query2.set_name(Name::from_str("_http._tcp.local.").unwrap());
        query2.set_query_type(RecordType::PTR);
        query2.set_query_class(DNSClass::IN);
        msg.add_query(query2);

        let entry = message_to_json(&msg, "eth0:v4", "10.0.0.1:5353", 100, "2024-01-01T00:00:00Z");

        // QU bit question: class should be "IN", prefer_unicast should be true
        assert_eq!(entry.message.questions[0].class, "IN");
        assert_eq!(entry.message.questions[0].prefer_unicast, Some(true));

        // Normal question: class should be "IN", no prefer_unicast
        assert_eq!(entry.message.questions[1].class, "IN");
        assert_eq!(entry.message.questions[1].prefer_unicast, None);
    }
}

