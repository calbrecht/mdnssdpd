use anyhow::Result;
use hickory_proto::op::Message;
use regex::Regex;

use super::{filter_section, RecordMatcher, Section, Transform};

/// Remove records matching criteria from specified sections.
pub struct RemoveRecords {
    section: Section,
    matcher: RecordMatcher,
}

impl RemoveRecords {
    pub fn new(
        section: &str,
        record_type: Option<&str>,
        match_name: Option<&str>,
        match_rdata: Option<&str>,
    ) -> Result<Self> {
        Ok(Self {
            section: Section::parse(section)?,
            matcher: RecordMatcher::new(record_type, match_name, match_rdata)?,
        })
    }
}

impl Transform for RemoveRecords {
    fn apply(&self, msg: &mut Message) -> Result<bool> {
        filter_section(msg, &self.section, |r| self.matcher.matches(r));
        Ok(true)
    }
}

/// Remove services by name pattern from ALL sections including questions.
pub struct RemoveServices {
    name_regex: Regex,
}

impl RemoveServices {
    pub fn new(match_name: &str) -> Result<Self> {
        Ok(Self {
            name_regex: Regex::new(match_name)?,
        })
    }
}

impl Transform for RemoveServices {
    fn apply(&self, msg: &mut Message) -> Result<bool> {
        // Remove matching questions
        let queries: Vec<_> = msg
            .take_queries()
            .into_iter()
            .filter(|q| !self.name_regex.is_match(&q.name().to_string()))
            .collect();
        msg.add_queries(queries);

        // Remove matching records from all sections
        let re = &self.name_regex;
        filter_section(msg, &Section::All, |r| {
            re.is_match(&r.name().to_string())
        });

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn make_a_record(name: &str, ip: Ipv4Addr) -> Record {
        Record::from_rdata(
            Name::from_str(name).unwrap(),
            120,
            RData::A(A(ip)),
        )
    }

    fn make_aaaa_record(name: &str, ip: Ipv6Addr) -> Record {
        Record::from_rdata(
            Name::from_str(name).unwrap(),
            120,
            RData::AAAA(AAAA(ip)),
        )
    }

    #[test]
    fn test_remove_link_local_ipv6_from_answers() {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.add_answer(make_a_record("streamer.local.", Ipv4Addr::new(192, 168, 1, 100)));
        msg.add_answer(make_aaaa_record(
            "streamer.local.",
            "fe80::1".parse().unwrap(),
        ));
        msg.add_answer(make_aaaa_record(
            "streamer.local.",
            "2001:db8::1".parse().unwrap(),
        ));

        assert_eq!(msg.answers().len(), 3);

        let transform = RemoveRecords::new("answers", Some("AAAA"), None, Some("fe80")).unwrap();
        transform.apply(&mut msg).unwrap();

        assert_eq!(msg.answers().len(), 2);
        assert_eq!(msg.answers()[0].record_type(), RecordType::A);
        assert_eq!(msg.answers()[1].record_type(), RecordType::AAAA);
    }

    #[test]
    fn test_remove_link_local_ipv6_from_all_sections() {
        // Reproduces the real Tidal Connect scenario: fe80 AAAA in additionals
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);

        // PTR answer
        msg.add_answer(Record::from_rdata(
            Name::from_str("_tidalconnect._tcp.local.").unwrap(),
            4500,
            RData::PTR(hickory_proto::rr::rdata::PTR(
                Name::from_str("S3._tidalconnect._tcp.local.").unwrap(),
            )),
        ));

        // Additionals: A, global AAAA, link-local AAAA
        msg.add_additional(make_a_record("streamer.local.", Ipv4Addr::new(192, 168, 37, 114)));
        msg.add_additional(make_aaaa_record(
            "streamer.local.",
            "2001:db8::1".parse().unwrap(),
        ));
        msg.add_additional(make_aaaa_record(
            "streamer.local.",
            "fe80::521e:2dff:fe95:226a".parse().unwrap(),
        ));

        assert_eq!(msg.additionals().len(), 3);

        let transform = RemoveRecords::new("all", Some("AAAA"), None, Some("fe80")).unwrap();
        transform.apply(&mut msg).unwrap();

        // PTR answer preserved
        assert_eq!(msg.answers().len(), 1);
        // A and global AAAA preserved, link-local stripped
        assert_eq!(msg.additionals().len(), 2);
        assert_eq!(msg.additionals()[0].record_type(), RecordType::A);
        assert_eq!(msg.additionals()[1].record_type(), RecordType::AAAA);
        // Verify the remaining AAAA is the global one, not link-local
        let rdata_str = format!("{}", msg.additionals()[1].data());
        assert!(
            rdata_str.contains("2001:"),
            "Remaining AAAA should be global, got: {rdata_str}"
        );
    }

    #[test]
    fn test_remove_all_aaaa() {
        let mut msg = Message::new();
        msg.add_answer(make_a_record("a.local.", Ipv4Addr::new(10, 0, 0, 1)));
        msg.add_answer(make_aaaa_record("a.local.", "::1".parse().unwrap()));
        msg.add_additional(make_aaaa_record("b.local.", "::2".parse().unwrap()));

        let transform = RemoveRecords::new("all", Some("AAAA"), None, None).unwrap();
        transform.apply(&mut msg).unwrap();

        assert_eq!(msg.answers().len(), 1);
        assert_eq!(msg.additionals().len(), 0);
    }

    #[test]
    fn test_remove_services_leaves_empty_message() {
        use hickory_proto::op::Query;


        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query);

        // A query for _googlecast only
        let mut query = Query::new();
        query.set_name(Name::from_str("_googlecast._tcp.local.").unwrap());
        query.set_query_type(RecordType::PTR);
        msg.add_query(query);

        let transform = RemoveServices::new("_googlecast").unwrap();
        transform.apply(&mut msg).unwrap();

        assert!(msg.queries().is_empty(), "Questions should be empty after stripping");
        assert!(msg.answers().is_empty());
        assert!(msg.name_servers().is_empty());
        assert!(msg.additionals().is_empty());
    }

    #[test]
    fn test_remove_services_partial_strip() {
        use hickory_proto::op::Query;

        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query);

        // Two questions: one google, one tidal
        let mut q1 = Query::new();
        q1.set_name(Name::from_str("_googlecast._tcp.local.").unwrap());
        q1.set_query_type(RecordType::PTR);
        msg.add_query(q1);

        let mut q2 = Query::new();
        q2.set_name(Name::from_str("_tidalconnect._tcp.local.").unwrap());
        q2.set_query_type(RecordType::PTR);
        msg.add_query(q2);

        let transform = RemoveServices::new("_googlecast").unwrap();
        transform.apply(&mut msg).unwrap();

        assert_eq!(msg.queries().len(), 1, "Only tidal question should remain");
        assert_eq!(
            msg.queries()[0].name().to_string(),
            "_tidalconnect._tcp.local."
        );
    }

    #[test]
    fn test_remove_from_authorities_only() {
        let mut msg = Message::new();
        msg.add_answer(make_aaaa_record("a.local.", "::1".parse().unwrap()));
        msg.add_name_server(make_aaaa_record("ns.local.", "::2".parse().unwrap()));

        RemoveRecords::new("authorities", Some("AAAA"), None, None).unwrap()
            .apply(&mut msg).unwrap();

        assert_eq!(msg.answers().len(), 1); // untouched
        assert_eq!(msg.name_servers().len(), 0);
    }

    #[test]
    fn test_remove_from_additionals_only() {
        let mut msg = Message::new();
        msg.add_answer(make_a_record("a.local.", Ipv4Addr::new(10, 0, 0, 1)));
        msg.add_additional(make_aaaa_record("add.local.", "::1".parse().unwrap()));

        RemoveRecords::new("additionals", Some("AAAA"), None, None).unwrap()
            .apply(&mut msg).unwrap();

        assert_eq!(msg.answers().len(), 1);
        assert_eq!(msg.additionals().len(), 0);
    }

    #[test]
    fn test_remove_no_matches() {
        let mut msg = Message::new();
        msg.add_answer(make_a_record("a.local.", Ipv4Addr::new(10, 0, 0, 1)));

        RemoveRecords::new("all", Some("AAAA"), None, None).unwrap()
            .apply(&mut msg).unwrap();

        assert_eq!(msg.answers().len(), 1); // unchanged
    }

    #[test]
    fn test_remove_by_name_regex_only() {
        let mut msg = Message::new();
        msg.add_answer(make_a_record("google.local.", Ipv4Addr::new(10, 0, 0, 1)));
        msg.add_answer(make_a_record("tidal.local.", Ipv4Addr::new(10, 0, 0, 2)));

        RemoveRecords::new("answers", None, Some("google"), None).unwrap()
            .apply(&mut msg).unwrap();

        assert_eq!(msg.answers().len(), 1);
        assert!(msg.answers()[0].name().to_string().contains("tidal"));
    }

    #[test]
    fn test_remove_by_rdata_regex_only() {
        let mut msg = Message::new();
        msg.add_answer(make_a_record("a.local.", Ipv4Addr::new(10, 0, 0, 1)));
        msg.add_answer(make_a_record("b.local.", Ipv4Addr::new(192, 168, 1, 1)));

        RemoveRecords::new("answers", None, None, Some("^10\\.")).unwrap()
            .apply(&mut msg).unwrap();

        assert_eq!(msg.answers().len(), 1);
        assert!(format!("{}", msg.answers()[0].data()).contains("192.168"));
    }

    #[test]
    fn test_remove_empty_message() {
        let mut msg = Message::new();
        // Should not panic
        RemoveRecords::new("all", Some("A"), None, None).unwrap()
            .apply(&mut msg).unwrap();
        assert!(msg.answers().is_empty());
    }

    #[test]
    fn test_remove_services_no_matches() {
        use hickory_proto::op::Query;

        let mut msg = Message::new();
        let mut q = Query::new();
        q.set_name(Name::from_str("_tidal._tcp.local.").unwrap());
        q.set_query_type(RecordType::PTR);
        msg.add_query(q);
        msg.add_answer(make_a_record("tidal.local.", Ipv4Addr::new(10, 0, 0, 1)));

        RemoveServices::new("_googlecast").unwrap().apply(&mut msg).unwrap();

        assert_eq!(msg.queries().len(), 1); // unchanged
        assert_eq!(msg.answers().len(), 1);
    }

    #[test]
    fn test_remove_services_from_answers_and_additionals() {
        let mut msg = Message::new();
        msg.add_answer(Record::from_rdata(
            Name::from_str("_googlecast._tcp.local.").unwrap(), 120,
            RData::PTR(hickory_proto::rr::rdata::PTR(
                Name::from_str("device._googlecast._tcp.local.").unwrap(),
            )),
        ));
        msg.add_answer(make_a_record("tidal.local.", Ipv4Addr::new(10, 0, 0, 1)));
        msg.add_additional(Record::from_rdata(
            Name::from_str("device._googlecast._tcp.local.").unwrap(), 120,
            RData::A(A(Ipv4Addr::new(10, 0, 0, 2))),
        ));

        RemoveServices::new("_googlecast").unwrap().apply(&mut msg).unwrap();

        assert_eq!(msg.answers().len(), 1); // only tidal remains
        assert_eq!(msg.additionals().len(), 0);
    }
}
