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
}

impl Output for LogOutput {
    fn emit(&self, ctx: &OutputContext) -> Result<()> {
        let entry = dns_util::message_to_json(
            ctx.msg,
            &ctx.event.interface,
            &format!("{}", ctx.event.source),
            ctx.event.data.len(),
            &ctx.event.timestamp,
        );

        match self.format.as_str() {
            "json" => {
                let json = serde_json::to_string(&entry)?;
                println!("{}", json);
            }
            _ => {
                let json = serde_json::to_string(&entry)?;
                println!("{}", json);
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "log"
    }
}
