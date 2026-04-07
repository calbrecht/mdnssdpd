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
            section: Section::parse(section),
            matcher: RecordMatcher::new(record_type, match_name, match_rdata)?,
        })
    }
}

impl Transform for RemoveRecords {
    fn apply(&self, msg: &mut Message) -> Result<bool> {
        filter_section(msg, &self.section, |r| self.matcher.matches(r));
        Ok(true)
    }

    fn name(&self) -> &str {
        "remove_records"
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

    fn name(&self) -> &str {
        "remove_services"
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
    fn test_remove_link_local_ipv6() {
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
        // A record still there
        assert_eq!(msg.answers()[0].record_type(), RecordType::A);
        // Global AAAA still there
        assert_eq!(msg.answers()[1].record_type(), RecordType::AAAA);
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
}
