pub mod remove_records;
pub mod set_ttl;

use anyhow::Result;
use hickory_proto::op::Message;
use hickory_proto::rr::{Record, RecordType};
use regex::Regex;

use crate::config::TransformConfig;

/// Which record sections to operate on.
#[derive(Debug, Clone)]
pub enum Section {
    Answers,
    Authorities,
    Additionals,
    All,
}

impl Section {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "answers" => Ok(Self::Answers),
            "authorities" => Ok(Self::Authorities),
            "additionals" => Ok(Self::Additionals),
            "all" => Ok(Self::All),
            other => Err(anyhow::anyhow!("Unknown section '{}'. Expected: answers, authorities, additionals, all", other)),
        }
    }
}

/// Matches records by type, name regex, and/or rdata regex.
#[derive(Clone)]
pub struct RecordMatcher {
    pub record_type: Option<RecordType>,
    pub name_regex: Option<Regex>,
    pub rdata_regex: Option<Regex>,
}

impl RecordMatcher {
    pub fn new(
        record_type: Option<&str>,
        name_regex: Option<&str>,
        rdata_regex: Option<&str>,
    ) -> Result<Self> {
        let record_type = match record_type {
            Some(rt) => Some(
                rt.parse::<RecordType>()
                    .map_err(|_| anyhow::anyhow!("Unknown record type: {}", rt))?,
            ),
            None => None,
        };
        let name_regex = match name_regex {
            Some(r) => Some(Regex::new(r)?),
            None => None,
        };
        let rdata_regex = match rdata_regex {
            Some(r) => Some(Regex::new(r)?),
            None => None,
        };
        Ok(Self {
            record_type,
            name_regex,
            rdata_regex,
        })
    }

    pub fn matches(&self, record: &Record) -> bool {
        if let Some(rt) = &self.record_type {
            if record.record_type() != *rt {
                return false;
            }
        }
        if let Some(re) = &self.name_regex {
            if !re.is_match(&record.name().to_string()) {
                return false;
            }
        }
        if let Some(re) = &self.rdata_regex {
            // Use Display format for human-readable rdata (e.g. "fe80::1"),
            // not Debug which wraps in type constructors (e.g. "AAAA(AAAA(fe80::1))")
            let rdata_str = format!("{}", record.data());
            if !re.is_match(&rdata_str) {
                return false;
            }
        }
        true
    }
}

/// A transform that can modify a DNS message in-place.
pub trait Transform: Send + Sync {
    /// Apply the transform. Return Ok(true) to continue, Ok(false) to drop the packet.
    fn apply(&self, msg: &mut Message) -> Result<bool>;
}

/// An ordered chain of transforms.
pub struct TransformChain {
    transforms: Vec<Box<dyn Transform>>,
}

impl TransformChain {
    pub fn new(transforms: Vec<Box<dyn Transform>>) -> Self {
        Self { transforms }
    }

    pub fn apply(&self, msg: &mut Message) -> Result<bool> {
        for t in &self.transforms {
            if !t.apply(msg)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn is_empty(&self) -> bool {
        self.transforms.is_empty()
    }
}

/// Filter records in a section, keeping only those that DON'T match the predicate.
pub fn filter_section(msg: &mut Message, section: &Section, should_remove: impl Fn(&Record) -> bool) {
    match section {
        Section::Answers => {
            let records: Vec<Record> = msg.take_answers().into_iter().filter(|r| !should_remove(r)).collect();
            msg.insert_answers(records);
        }
        Section::Authorities => {
            let records: Vec<Record> = msg.take_name_servers().into_iter().filter(|r| !should_remove(r)).collect();
            msg.insert_name_servers(records);
        }
        Section::Additionals => {
            let records: Vec<Record> = msg.take_additionals().into_iter().filter(|r| !should_remove(r)).collect();
            msg.insert_additionals(records);
        }
        Section::All => {
            let f = &should_remove;
            let answers: Vec<Record> = msg.take_answers().into_iter().filter(|r| !f(r)).collect();
            msg.insert_answers(answers);
            let ns: Vec<Record> = msg.take_name_servers().into_iter().filter(|r| !f(r)).collect();
            msg.insert_name_servers(ns);
            let add: Vec<Record> = msg.take_additionals().into_iter().filter(|r| !f(r)).collect();
            msg.insert_additionals(add);
        }
    }
}

/// Mutate records in a section.
pub fn mutate_section(msg: &mut Message, section: &Section, mutate: impl Fn(&mut Record)) {
    match section {
        Section::Answers => {
            for r in msg.answers_mut() { mutate(r); }
        }
        Section::Authorities => {
            for r in msg.name_servers_mut() { mutate(r); }
        }
        Section::Additionals => {
            for r in msg.additionals_mut() { mutate(r); }
        }
        Section::All => {
            for r in msg.answers_mut() { mutate(r); }
            for r in msg.name_servers_mut() { mutate(r); }
            for r in msg.additionals_mut() { mutate(r); }
        }
    }
}

/// Build a TransformChain from config.
pub fn build_chain(configs: &[TransformConfig]) -> Result<TransformChain> {
    let mut transforms: Vec<Box<dyn Transform>> = Vec::new();

    for config in configs {
        let t: Box<dyn Transform> = match config {
            TransformConfig::RemoveRecords {
                section,
                record_type,
                match_name,
                match_rdata,
            } => Box::new(remove_records::RemoveRecords::new(
                section,
                record_type.as_deref(),
                match_name.as_deref(),
                match_rdata.as_deref(),
            )?),
            TransformConfig::SetTtl {
                section,
                value,
                record_type,
            } => Box::new(set_ttl::SetTtl::new(
                section,
                *value,
                record_type.as_deref(),
            )?),
            TransformConfig::RemoveServices { match_name } => {
                Box::new(remove_records::RemoveServices::new(match_name)?)
            }
        };
        transforms.push(t);
    }

    Ok(TransformChain::new(transforms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Message;
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn make_record(name: &str) -> Record {
        Record::from_rdata(
            Name::from_str(name).unwrap(),
            120,
            RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
        )
    }

    fn make_aaaa_record(name: &str) -> Record {
        Record::from_rdata(
            Name::from_str(name).unwrap(),
            120,
            RData::AAAA(AAAA("fe80::1".parse().unwrap())),
        )
    }

    // --- Section::parse ---

    #[test]
    fn test_section_parse_all_variants() {
        assert!(matches!(Section::parse("answers").unwrap(), Section::Answers));
        assert!(matches!(Section::parse("authorities").unwrap(), Section::Authorities));
        assert!(matches!(Section::parse("additionals").unwrap(), Section::Additionals));
        assert!(matches!(Section::parse("all").unwrap(), Section::All));
    }

    #[test]
    fn test_section_parse_invalid() {
        assert!(Section::parse("unknown").is_err());
        assert!(Section::parse("").is_err());
        assert!(Section::parse("answres").is_err()); // typo
        assert!(Section::parse("ALL").is_err()); // case sensitive
        assert!(Section::parse("Answers").is_err()); // case sensitive
    }

    #[test]
    fn test_section_parse_error_message() {
        let err = Section::parse("answres").unwrap_err();
        assert!(err.to_string().contains("answres"));
        assert!(err.to_string().contains("answers"));
    }

    #[test]
    fn test_section_default_from_config_is_all() {
        // config.rs sets default_section_all() -> "all"
        // verify that "all" is accepted
        assert!(matches!(Section::parse("all").unwrap(), Section::All));
    }

    // --- RecordMatcher ---

    #[test]
    fn test_matcher_no_filters() {
        let m = RecordMatcher::new(None, None, None).unwrap();
        assert!(m.matches(&make_record("test.local.")));
    }

    #[test]
    fn test_matcher_record_type_only() {
        let m = RecordMatcher::new(Some("A"), None, None).unwrap();
        assert!(m.matches(&make_record("test.local.")));
        assert!(!m.matches(&make_aaaa_record("test.local.")));
    }

    #[test]
    fn test_matcher_name_regex_only() {
        let m = RecordMatcher::new(None, Some("test"), None).unwrap();
        assert!(m.matches(&make_record("test.local.")));
        assert!(!m.matches(&make_record("other.local.")));
    }

    #[test]
    fn test_matcher_rdata_regex_only() {
        let m = RecordMatcher::new(None, None, Some("fe80")).unwrap();
        assert!(m.matches(&make_aaaa_record("x.local.")));
        assert!(!m.matches(&make_record("x.local."))); // A record rdata is 10.0.0.1
    }

    #[test]
    fn test_matcher_all_filters_combined() {
        let m = RecordMatcher::new(Some("AAAA"), Some("x\\.local"), Some("fe80")).unwrap();
        assert!(m.matches(&make_aaaa_record("x.local.")));
        // Wrong type
        assert!(!m.matches(&make_record("x.local.")));
    }

    #[test]
    fn test_matcher_invalid_regex() {
        assert!(RecordMatcher::new(None, Some("[invalid"), None).is_err());
        assert!(RecordMatcher::new(None, None, Some("[invalid")).is_err());
    }

    #[test]
    fn test_matcher_invalid_record_type() {
        assert!(RecordMatcher::new(Some("NOTARECORDTYPE"), None, None).is_err());
    }

    // --- filter_section ---

    #[test]
    fn test_filter_section_answers() {
        let mut msg = Message::new();
        msg.add_answer(make_record("keep.local."));
        msg.add_answer(make_aaaa_record("remove.local."));
        msg.add_name_server(make_aaaa_record("authority.local."));

        filter_section(&mut msg, &Section::Answers, |r| {
            r.record_type() == hickory_proto::rr::RecordType::AAAA
        });

        assert_eq!(msg.answers().len(), 1);
        assert_eq!(msg.name_servers().len(), 1); // untouched
    }

    #[test]
    fn test_filter_section_authorities() {
        let mut msg = Message::new();
        msg.add_answer(make_record("answer.local."));
        msg.add_name_server(make_record("ns1.local."));
        msg.add_name_server(make_record("ns2.local."));

        filter_section(&mut msg, &Section::Authorities, |_| true); // remove all

        assert_eq!(msg.answers().len(), 1); // untouched
        assert_eq!(msg.name_servers().len(), 0);
    }

    #[test]
    fn test_filter_section_additionals() {
        let mut msg = Message::new();
        msg.add_additional(make_record("a.local."));
        msg.add_additional(make_record("b.local."));

        filter_section(&mut msg, &Section::Additionals, |_| true);

        assert_eq!(msg.additionals().len(), 0);
    }

    #[test]
    fn test_filter_section_all() {
        let mut msg = Message::new();
        msg.add_answer(make_record("a.local."));
        msg.add_name_server(make_record("ns.local."));
        msg.add_additional(make_record("add.local."));

        filter_section(&mut msg, &Section::All, |_| true);

        assert_eq!(msg.answers().len(), 0);
        assert_eq!(msg.name_servers().len(), 0);
        assert_eq!(msg.additionals().len(), 0);
    }

    // --- mutate_section ---

    #[test]
    fn test_mutate_section_answers() {
        let mut msg = Message::new();
        msg.add_answer(make_record("a.local."));
        msg.add_name_server(make_record("ns.local."));

        mutate_section(&mut msg, &Section::Answers, |r| { r.set_ttl(999); });

        assert_eq!(msg.answers()[0].ttl(), 999);
        assert_eq!(msg.name_servers()[0].ttl(), 120); // untouched
    }

    #[test]
    fn test_mutate_section_all() {
        let mut msg = Message::new();
        msg.add_answer(make_record("a.local."));
        msg.add_name_server(make_record("ns.local."));
        msg.add_additional(make_record("add.local."));

        mutate_section(&mut msg, &Section::All, |r| { r.set_ttl(42); });

        assert_eq!(msg.answers()[0].ttl(), 42);
        assert_eq!(msg.name_servers()[0].ttl(), 42);
        assert_eq!(msg.additionals()[0].ttl(), 42);
    }

    // --- TransformChain ---

    #[test]
    fn test_chain_empty() {
        let chain = TransformChain::new(vec![]);
        assert!(chain.is_empty());
        let mut msg = Message::new();
        assert!(chain.apply(&mut msg).unwrap());
    }

    #[test]
    fn test_chain_applies_in_order() {
        // Two SetTtl transforms: first sets 60, second sets 30
        let t1 = Box::new(set_ttl::SetTtl::new("answers", 60, None).unwrap());
        let t2 = Box::new(set_ttl::SetTtl::new("answers", 30, None).unwrap());
        let chain = TransformChain::new(vec![t1, t2]);
        assert!(!chain.is_empty());

        let mut msg = Message::new();
        msg.add_answer(make_record("a.local."));
        chain.apply(&mut msg).unwrap();
        assert_eq!(msg.answers()[0].ttl(), 30); // second wins
    }

    // --- build_chain ---

    #[test]
    fn test_build_chain_empty() {
        let chain = build_chain(&[]).unwrap();
        assert!(chain.is_empty());
    }

    #[test]
    fn test_build_chain_multiple() {
        let configs = vec![
            TransformConfig::SetTtl {
                section: "answers".into(),
                value: 60,
                record_type: None,
            },
            TransformConfig::RemoveRecords {
                section: "all".into(),
                record_type: Some("AAAA".into()),
                match_name: None,
                match_rdata: None,
            },
        ];
        let chain = build_chain(&configs).unwrap();
        assert!(!chain.is_empty());
    }

    #[test]
    fn test_build_chain_remove_services() {
        let configs = vec![
            TransformConfig::RemoveServices {
                match_name: "_googlecast".into(),
            },
        ];
        let chain = build_chain(&configs).unwrap();
        assert!(!chain.is_empty());
    }

    // --- TransformChain early exit on false ---

    struct DropTransform;
    impl Transform for DropTransform {
        fn apply(&self, _msg: &mut Message) -> Result<bool> { Ok(false) }
    }

    struct PanicTransform;
    impl Transform for PanicTransform {
        fn apply(&self, _msg: &mut Message) -> Result<bool> { panic!("should not be called") }
    }

    #[test]
    fn test_chain_early_exit_on_false() {
        // First transform drops, second should never run
        let chain = TransformChain::new(vec![
            Box::new(DropTransform),
            Box::new(PanicTransform),
        ]);
        let mut msg = Message::new();
        assert!(!chain.apply(&mut msg).unwrap());
    }

    // --- mutate_section individual branches ---

    #[test]
    fn test_mutate_section_authorities() {
        let mut msg = Message::new();
        msg.add_answer(make_record("a.local."));
        msg.add_name_server(make_record("ns.local."));

        mutate_section(&mut msg, &Section::Authorities, |r| { r.set_ttl(7); });

        assert_eq!(msg.answers()[0].ttl(), 120); // untouched
        assert_eq!(msg.name_servers()[0].ttl(), 7);
    }

    #[test]
    fn test_mutate_section_additionals() {
        let mut msg = Message::new();
        msg.add_answer(make_record("a.local."));
        msg.add_additional(make_record("add.local."));

        mutate_section(&mut msg, &Section::Additionals, |r| { r.set_ttl(3); });

        assert_eq!(msg.answers()[0].ttl(), 120); // untouched
        assert_eq!(msg.additionals()[0].ttl(), 3);
    }

}
