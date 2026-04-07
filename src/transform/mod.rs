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
    pub fn parse(s: &str) -> Self {
        match s {
            "answers" => Self::Answers,
            "authorities" => Self::Authorities,
            "additionals" => Self::Additionals,
            _ => Self::All,
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
            let rdata_str = format!("{:?}", record.data());
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
    fn name(&self) -> &str;
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
