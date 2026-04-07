use anyhow::Result;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;

use super::{mutate_section, Section, Transform};

/// Set TTL on matching records. Respects TTL=0 (mDNS goodbye) — never overwrites it.
pub struct SetTtl {
    section: Section,
    value: u32,
    record_type: Option<RecordType>,
}

impl SetTtl {
    pub fn new(section: &str, value: u32, record_type: Option<&str>) -> Result<Self> {
        let record_type = match record_type {
            Some(rt) => Some(
                rt.parse::<RecordType>()
                    .map_err(|_| anyhow::anyhow!("Unknown record type: {}", rt))?,
            ),
            None => None,
        };
        Ok(Self {
            section: Section::parse(section),
            value,
            record_type,
        })
    }
}

impl Transform for SetTtl {
    fn apply(&self, msg: &mut Message) -> Result<bool> {
        let rt = self.record_type;
        let ttl_val = self.value;

        mutate_section(msg, &self.section, |r| {
            // Don't touch TTL=0 (mDNS goodbye announcement)
            if r.ttl() == 0 {
                return;
            }
            if let Some(expected_rt) = rt {
                if r.record_type() != expected_rt {
                    return;
                }
            }
            r.set_ttl(ttl_val);
        });

        Ok(true)
    }

    fn name(&self) -> &str {
        "set_ttl"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Message;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn make_record(name: &str, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
        )
    }

    #[test]
    fn test_set_ttl() {
        let mut msg = Message::new();
        msg.add_answer(make_record("a.local.", 120));
        msg.add_answer(make_record("b.local.", 300));

        let transform = SetTtl::new("answers", 60, None).unwrap();
        transform.apply(&mut msg).unwrap();

        assert_eq!(msg.answers()[0].ttl(), 60);
        assert_eq!(msg.answers()[1].ttl(), 60);
    }

    #[test]
    fn test_preserves_goodbye() {
        let mut msg = Message::new();
        msg.add_answer(make_record("a.local.", 0)); // goodbye
        msg.add_answer(make_record("b.local.", 120));

        let transform = SetTtl::new("answers", 60, None).unwrap();
        transform.apply(&mut msg).unwrap();

        assert_eq!(msg.answers()[0].ttl(), 0); // preserved
        assert_eq!(msg.answers()[1].ttl(), 60);
    }
}
