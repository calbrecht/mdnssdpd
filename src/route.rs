use std::collections::HashSet;

use anyhow::Result;
use crate::config::{RouteConfig, RouteFilterConfig};
use crate::dns_util;
use crate::filter::{self, FilterConfig, FilterEngine};
use crate::output::{self, Output, OutputContext};
use crate::receiver::PacketEvent;
use crate::transform::{self, TransformChain};

/// A compiled route: input filter → transform → outputs.
pub struct Route {
    pub name: String,
    pub input_interfaces: HashSet<String>,
    filter: Option<FilterEngine>,
    transforms: TransformChain,
    outputs: Vec<Box<dyn Output>>,
}

impl Route {
    pub fn build(config: &RouteConfig) -> Result<Self> {
        let input_interfaces: HashSet<String> = config.input.iter().cloned().collect();

        // Build filter engine from route filter config
        let filter = match &config.filter {
            Some(fc) => build_route_filter(fc)?,
            None => None,
        };

        // Build transform chain
        let transforms = transform::build_chain(&config.transform)?;

        // Build outputs
        let outputs = output::build_outputs(&config.output)?;

        eprintln!(
            "[route:{}] input={:?} transforms={} outputs={}",
            config.name,
            config.input,
            config.transform.len(),
            outputs.len(),
        );

        Ok(Self {
            name: config.name.clone(),
            input_interfaces,
            filter,
            transforms,
            outputs,
        })
    }

    /// Process a received packet through this route's pipeline.
    pub fn process(&self, event: &PacketEvent) -> Result<()> {
        // Check if this packet is from one of our input interfaces
        // Match on base interface name (strip :v4/:v6 suffix)
        let base_iface = event.interface.split(':').next().unwrap_or(&event.interface);
        if !self.input_interfaces.contains(base_iface) && !self.input_interfaces.contains(&event.interface) {
            return Ok(());
        }

        // Parse
        let mut msg = match dns_util::parse_message(&event.data) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[route:{}] Parse error from {}: {}", self.name, event.source, e);
                return Ok(());
            }
        };

        // Filter (on JSON representation)
        if let Some(filter) = &self.filter {
            let json_entry = serde_json::to_value(&dns_util::message_to_json(
                &msg,
                &event.interface,
                &format!("{}", event.source),
                event.data.len(),
                &event.timestamp,
            ))?;
            if !filter.should_print(&json_entry) {
                return Ok(());
            }
        }

        // Transform (on Message, in-place)
        if !self.transforms.apply(&mut msg)? {
            return Ok(()); // transform dropped the packet
        }

        // Re-serialize for reflect outputs
        let wire_bytes = if self.transforms.is_empty() {
            // No transforms — use original bytes (faster, preserves wire format exactly)
            event.data.clone()
        } else {
            msg.to_vec()?
        };

        // Output
        let ctx = OutputContext {
            event,
            msg: &msg,
            wire_bytes: &wire_bytes,
        };

        for output in &self.outputs {
            if let Err(e) = output.emit(&ctx) {
                eprintln!("[route:{}] Output {} error: {}", self.name, output.name(), e);
            }
        }

        Ok(())
    }
}

/// Convert RouteFilterConfig into what FilterEngine::build expects.
fn build_route_filter(rfc: &RouteFilterConfig) -> Result<Option<FilterEngine>> {
    // Load chain files
    let chain_configs = filter::load_configs(&rfc.chain)?;

    // Convert inline rules to a FilterConfig
    let inline_config = FilterConfig {
        chain: vec![],
        mode: rfc.mode.clone(),
        action: rfc.action.clone(),
        rule: rfc
            .rule
            .iter()
            .map(|r| filter::Rule {
                name: r.name.clone(),
                negate: r.negate,
                condition: r
                    .condition
                    .iter()
                    .map(|c| filter::Condition {
                        path: c.path.clone(),
                        op: c.op.clone(),
                        value: c.value.clone(),
                    })
                    .collect(),
            })
            .collect(),
    };

    // Merge: chain configs first, then inline config (if it has rules)
    let mut all_configs = chain_configs;
    if !inline_config.rule.is_empty() {
        all_configs.push(inline_config);
    }

    FilterEngine::build(all_configs, &[], &rfc.jq, false)
}
