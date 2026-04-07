use anyhow::Result;

use crate::sender::MdnsSender;
use super::{Output, OutputContext};

pub struct ReflectOutput {
    sender: MdnsSender,
}

impl ReflectOutput {
    pub fn new(iface: &str) -> Result<Self> {
        let sender = MdnsSender::new_v4(iface)?;
        eprintln!("[reflect] Sender ready on {}", iface);
        Ok(Self { sender })
    }
}

impl Output for ReflectOutput {
    fn emit(&self, ctx: &OutputContext) -> Result<()> {
        self.sender.send(ctx.wire_bytes)?;
        Ok(())
    }

    fn name(&self) -> &str {
        "reflect"
    }
}
