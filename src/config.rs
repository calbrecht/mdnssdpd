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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_input_interfaces_dedup() {
        let config = Config {
            route: vec![
                RouteConfig {
                    name: "r1".into(),
                    input: vec!["eth0".into(), "eth1".into()],
                    filter: None,
                    transform: vec![],
                    output: vec![OutputConfig::Log { format: "json".into() }],
                },
                RouteConfig {
                    name: "r2".into(),
                    input: vec!["eth1".into(), "eth2".into()],
                    filter: None,
                    transform: vec![],
                    output: vec![OutputConfig::Log { format: "json".into() }],
                },
            ],
        };
        let ifaces = config.all_input_interfaces();
        assert_eq!(ifaces, vec!["eth0", "eth1", "eth2"]);
    }

    #[test]
    fn test_all_input_interfaces_empty() {
        let config = Config { route: vec![] };
        assert!(config.all_input_interfaces().is_empty());
    }

    #[test]
    fn test_deserialize_minimal_config() {
        let toml_str = r#"
            [[route]]
            name = "test"
            input = ["eth0"]
            output = [{ type = "log" }]
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.route.len(), 1);
        assert_eq!(config.route[0].name, "test");
        assert_eq!(config.route[0].input, vec!["eth0"]);
        assert!(config.route[0].filter.is_none());
        assert!(config.route[0].transform.is_empty());
    }

    #[test]
    fn test_deserialize_defaults() {
        let toml_str = r#"
            [[route]]
            name = "test"
            input = ["eth0"]
            output = [{ type = "log" }]

            [route.filter]
            [[route.filter.rule]]
            [[route.filter.rule.condition]]
            path = "source"
            op = "eq"
            value = "x"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let filter = config.route[0].filter.as_ref().unwrap();
        assert_eq!(filter.mode, "any");
        assert_eq!(filter.action, "show");
        assert!(filter.jq.is_empty());
        assert!(filter.chain.is_empty());
    }

    #[test]
    fn test_deserialize_transform_remove_records() {
        let toml_str = r#"
            [[route]]
            name = "test"
            input = ["eth0"]
            output = [{ type = "log" }]

            [[route.transform]]
            type = "remove_records"
            record_type = "AAAA"
            match_rdata = "^fe80"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.route[0].transform.len(), 1);
        match &config.route[0].transform[0] {
            TransformConfig::RemoveRecords { section, record_type, match_rdata, .. } => {
                assert_eq!(section, "all"); // default
                assert_eq!(record_type.as_deref(), Some("AAAA"));
                assert_eq!(match_rdata.as_deref(), Some("^fe80"));
            }
            _ => panic!("Expected RemoveRecords"),
        }
    }

    #[test]
    fn test_deserialize_transform_set_ttl() {
        let toml_str = r#"
            [[route]]
            name = "test"
            input = ["eth0"]
            output = [{ type = "log" }]

            [[route.transform]]
            type = "set_ttl"
            section = "answers"
            value = 60
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        match &config.route[0].transform[0] {
            TransformConfig::SetTtl { section, value, record_type } => {
                assert_eq!(section, "answers");
                assert_eq!(*value, 60);
                assert!(record_type.is_none());
            }
            _ => panic!("Expected SetTtl"),
        }
    }

    #[test]
    fn test_deserialize_output_reflect() {
        let toml_str = r#"
            [[route]]
            name = "test"
            input = ["eth0"]
            output = [{ type = "reflect", interfaces = ["eth1", "eth2"] }]
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        match &config.route[0].output[0] {
            OutputConfig::Reflect { interfaces } => {
                assert_eq!(interfaces, &vec!["eth1", "eth2"]);
            }
            _ => panic!("Expected Reflect"),
        }
    }

    #[test]
    fn test_load_from_file() {
        let dir = std::env::temp_dir().join("dnssd-test-config");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.toml");
        std::fs::write(&path, r#"
            [[route]]
            name = "test"
            input = ["eth0"]
            output = [{ type = "log" }]
        "#).unwrap();
        let config = Config::load(path.to_str().unwrap()).unwrap();
        assert_eq!(config.route[0].name, "test");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_nonexistent_file() {
        assert!(Config::load("/nonexistent/path.toml").is_err());
    }
}
