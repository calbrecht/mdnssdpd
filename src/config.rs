use serde::Deserialize;
use serde_json::Value;

use crate::filter::ops::Op;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub route: Vec<RouteConfig>,
}

#[derive(Debug, Deserialize)]
pub struct RouteConfig {
    pub name: String,
    /// Input interfaces to listen on
    pub input: Vec<String>,
    /// Filter configuration (same as standalone filter files)
    #[serde(default)]
    pub filter: Option<RouteFilterConfig>,
    /// Transform chain (applied in order)
    #[serde(default)]
    pub transform: Vec<TransformConfig>,
    /// Output sinks
    pub output: Vec<OutputConfig>,
}

/// Filter config embedded in a route — mirrors the standalone FilterConfig
/// but also supports jq expressions inline.
#[derive(Debug, Deserialize, Default)]
pub struct RouteFilterConfig {
    #[serde(default)]
    pub chain: Vec<String>,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub jq: Vec<String>,
    #[serde(default)]
    pub rule: Vec<RouteFilterRule>,
}

#[derive(Debug, Deserialize)]
pub struct RouteFilterRule {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub negate: bool,
    #[serde(default)]
    pub condition: Vec<RouteFilterCondition>,
}

#[derive(Debug, Deserialize)]
pub struct RouteFilterCondition {
    pub path: String,
    pub op: Op,
    pub value: Value,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum TransformConfig {
    #[serde(rename = "remove_records")]
    RemoveRecords {
        /// "answers", "authorities", "additionals", or "all"
        #[serde(default = "default_section_all")]
        section: String,
        /// Filter by record type (e.g., "AAAA")
        #[serde(default)]
        record_type: Option<String>,
        /// Regex on record name
        #[serde(default)]
        match_name: Option<String>,
        /// Regex on rdata string representation
        #[serde(default)]
        match_rdata: Option<String>,
    },
    #[serde(rename = "set_ttl")]
    SetTtl {
        #[serde(default = "default_section_all")]
        section: String,
        value: u32,
        #[serde(default)]
        record_type: Option<String>,
    },
    #[serde(rename = "remove_services")]
    RemoveServices {
        /// Regex on service name
        match_name: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum OutputConfig {
    #[serde(rename = "reflect")]
    Reflect {
        interfaces: Vec<String>,
    },
    #[serde(rename = "log")]
    Log {
        #[serde(default = "default_log_format")]
        format: String,
    },
}

fn default_mode() -> String { "any".into() }
fn default_action() -> String { "show".into() }
fn default_section_all() -> String { "all".into() }
fn default_log_format() -> String { "json".into() }

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config {}: {}", path, e))?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config {}: {}", path, e))?;
        Ok(config)
    }

    /// Collect all unique interface names referenced as inputs across all routes.
    pub fn all_input_interfaces(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for route in &self.route {
            for iface in &route.input {
                if seen.insert(iface.clone()) {
                    result.push(iface.clone());
                }
            }
        }
        result
    }
}
