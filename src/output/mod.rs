pub mod log;
pub mod reflect;

use anyhow::Result;
use hickory_proto::op::Message;

use crate::config::OutputConfig;
use crate::receiver::PacketEvent;

/// Context passed to outputs for each processed packet.
pub struct OutputContext<'a> {
    pub event: &'a PacketEvent,
    pub msg: &'a Message,
    pub wire_bytes: &'a [u8],
}

/// Output sink trait.
pub trait Output: Send + Sync {
    fn emit(&self, ctx: &OutputContext) -> Result<()>;
    fn name(&self) -> &str;
}

/// Build output sinks from config.
pub fn build_outputs(configs: &[OutputConfig]) -> Result<Vec<Box<dyn Output>>> {
    let mut outputs: Vec<Box<dyn Output>> = Vec::new();

    for config in configs {
        match config {
            OutputConfig::Log { format } => {
                outputs.push(Box::new(log::LogOutput::new(format)));
            }
            OutputConfig::Reflect { interfaces } => {
                for iface in interfaces {
                    let sender = reflect::ReflectOutput::new(iface)?;
                    outputs.push(Box::new(sender));
                }
            }
        }
    }

    Ok(outputs)
}
