pub mod ops;
pub mod path;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use jaq_core::load::{Arena, File, Loader};
use jaq_core::{Ctx, Vars};
use jaq_json::Val;
use serde::Deserialize;
use serde_json::Value;

use self::ops::{evaluate, Op};
use self::path::{parse_path, resolve, PathSegment};

// --- TOML config types ---

#[derive(Debug, Deserialize, Default)]
pub struct FilterConfig {
    /// Chain other filter files (ANDed together with this one)
    #[serde(default)]
    pub chain: Vec<String>,
    /// How rules within this file combine: "any" (OR, default) or "all" (AND)
    #[serde(default = "default_mode")]
    pub mode: String,
    /// "show" (default) = only print matches, "hide" = suppress matches
    #[serde(default = "default_action")]
    pub action: String,
    /// Filter rules
    #[serde(default)]
    pub rule: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub negate: bool,
    #[serde(default)]
    pub condition: Vec<Condition>,
}

#[derive(Debug, Deserialize)]
pub struct Condition {
    pub path: String,
    pub op: Op,
    pub value: Value,
}

fn default_mode() -> String { "any".into() }
fn default_action() -> String { "show".into() }

// --- Config loading with chain resolution ---

/// Load a single TOML config, then recursively resolve its `chain` entries.
/// Returns a flat list of configs in chain order (self first, then chained).
/// Tracks visited files to prevent cycles.
fn load_config_recursive(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
) -> Result<Vec<FilterConfig>> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Failed to resolve path: {}", path.display()))?;

    if !visited.insert(canonical.clone()) {
        anyhow::bail!("Circular chain detected: {}", path.display());
    }

    let content = std::fs::read_to_string(&canonical)
        .with_context(|| format!("Failed to read filter file: {}", path.display()))?;
    let config: FilterConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse filter file: {}", path.display()))?;

    let base_dir = canonical.parent().unwrap_or(Path::new("."));
    let chain_paths: Vec<PathBuf> = config
        .chain
        .iter()
        .map(|p| {
            let p = Path::new(p);
            if p.is_absolute() { p.to_path_buf() } else { base_dir.join(p) }
        })
        .collect();

    let mut result = vec![config];

    for chain_path in &chain_paths {
        let chained = load_config_recursive(chain_path, visited)?;
        result.extend(chained);
    }

    Ok(result)
}

/// Load filter configs from CLI paths, resolving chains.
pub fn load_configs(paths: &[String]) -> Result<Vec<FilterConfig>> {
    let mut visited = HashSet::new();
    let mut all_configs = Vec::new();

    for path_str in paths {
        let path = Path::new(path_str);
        let configs = load_config_recursive(path, &mut visited)?;
        all_configs.extend(configs);
    }

    Ok(all_configs)
}

// --- Compiled filter engine ---

/// Compiled jq filter, ready for repeated evaluation.
struct CompiledJq {
    filter: jaq_core::Filter<jaq_core::data::JustLut<Val>>,
}

impl CompiledJq {
    fn compile(program: &str) -> Result<Self> {
        let defs = jaq_core::defs().chain(jaq_std::defs()).chain(jaq_json::defs());
        let funs = jaq_core::funs().chain(jaq_std::funs()).chain(jaq_json::funs());

        let arena = Arena::default();
        let loader = Loader::new(defs);
        let modules = loader
            .load(&arena, File { path: (), code: program })
            .map_err(|errs| anyhow::anyhow!("jq parse error: {:?}", errs))?;

        let filter = jaq_core::Compiler::default()
            .with_funs(funs)
            .compile(modules)
            .map_err(|errs| anyhow::anyhow!("jq compile error: {:?}", errs))?;

        Ok(Self { filter })
    }

    fn is_truthy(&self, value: &Value) -> bool {
        let val: Val = match serde_json::from_value(value.clone()) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let ctx = Ctx::<jaq_core::data::JustLut<Val>>::new(&self.filter.lut, Vars::new([]));
        let out = self.filter.id.run((ctx, val));

        for result in out {
            match result {
                Ok(v) => match &v {
                    Val::Null | Val::Bool(false) => continue,
                    _ => return true,
                },
                Err(_) => continue,
            }
        }
        false
    }
}

/// A compiled condition with pre-parsed path.
struct CompiledCondition {
    segments: Vec<PathSegment>,
    op: Op,
    value: Value,
}

impl CompiledCondition {
    fn matches(&self, entry: &Value) -> bool {
        let resolved = resolve(entry, &self.segments);
        if resolved.is_empty() {
            return matches!(&self.op, Op::Exists) && self.value == Value::Bool(false);
        }
        resolved.iter().any(|v| evaluate(&self.op, v, &self.value))
    }
}

struct CompiledRule {
    negate: bool,
    conditions: Vec<CompiledCondition>,
}

impl CompiledRule {
    fn matches(&self, entry: &Value) -> bool {
        let result = self.conditions.iter().all(|c| c.matches(entry));
        if self.negate { !result } else { result }
    }
}

/// One link in the filter chain — compiled from a single FilterConfig.
struct ChainLink {
    rules: Vec<CompiledRule>,
    mode: FilterMode,
    action: FilterAction,
}

impl ChainLink {
    fn should_pass(&self, entry: &Value) -> bool {
        if self.rules.is_empty() {
            return true; // no rules = pass-through (chain-only file)
        }
        let matched = match self.mode {
            FilterMode::Any => self.rules.iter().any(|r| r.matches(entry)),
            FilterMode::All => self.rules.iter().all(|r| r.matches(entry)),
        };
        match self.action {
            FilterAction::Show => matched,
            FilterAction::Hide => !matched,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum FilterMode {
    Any,
    All,
}

#[derive(Debug, Clone, Copy)]
enum FilterAction {
    Show,
    Hide,
}

/// The main filter engine: a chain of TOML filters AND'd with jq filters.
pub struct FilterEngine {
    chain: Vec<ChainLink>,
    jq_filters: Vec<CompiledJq>,
}

impl FilterEngine {
    /// Build a filter engine from all sources.
    pub fn build(
        configs: Vec<FilterConfig>,
        jq_exprs: &[String],
    ) -> Result<Option<Self>> {
        let mut chain: Vec<ChainLink> = Vec::new();

        // Compile each config into a chain link
        for config in &configs {
            let mode = match config.mode.as_str() {
                "any" => FilterMode::Any,
                "all" => FilterMode::All,
                other => anyhow::bail!("Unknown filter mode '{}'. Expected: any, all", other),
            };
            let action = match config.action.as_str() {
                "show" => FilterAction::Show,
                "hide" => FilterAction::Hide,
                other => anyhow::bail!("Unknown filter action '{}'. Expected: show, hide", other),
            };

            let rules: Vec<CompiledRule> = config
                .rule
                .iter()
                .map(|rule| {
                    let conditions = rule
                        .condition
                        .iter()
                        .map(|c| CompiledCondition {
                            segments: parse_path(&c.path),
                            op: c.op.clone(),
                            value: c.value.clone(),
                        })
                        .collect();
                    CompiledRule {
                        negate: rule.negate,
                        conditions,
                    }
                })
                .collect();

            chain.push(ChainLink { rules, mode, action });
        }

        // Compile jq filters
        let mut jq_filters = Vec::new();
        for expr in jq_exprs {
            let compiled = CompiledJq::compile(expr)
                .with_context(|| format!("Failed to compile jq expression: {}", expr))?;
            jq_filters.push(compiled);
        }

        if chain.is_empty() && jq_filters.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self { chain, jq_filters }))
    }

    /// Check if a serialized log entry should be printed.
    pub fn should_print(&self, entry: &Value) -> bool {
        // Every chain link must pass (AND)
        let chain_pass = self.chain.iter().all(|link| link.should_pass(entry));
        // Every jq filter must be truthy (AND)
        let jq_pass = self.jq_filters.iter().all(|jq| jq.is_truthy(entry));
        chain_pass && jq_pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_filter(path: &str, op: Op, value: Value) -> FilterConfig {
        FilterConfig {
            mode: "any".into(),
            action: "show".into(),
            rule: vec![Rule {
                negate: false,
                condition: vec![Condition {
                    path: path.into(),
                    op,
                    value,
                }],
            }],
            chain: vec![],
        }
    }

    fn test_entry() -> Value {
        json!({
            "timestamp": "2024-01-01T00:00:00Z",
            "interface": "wlp0s20f3:v4",
            "source": "10.93.5.91:5353",
            "packet_size": 200,
            "message": {
                "id": 0,
                "message_type": "response",
                "opcode": "Query",
                "authoritative": true,
                "truncated": false,
                "question_count": 1,
                "answer_count": 2,
                "questions": [
                    {"name": "_http._tcp.local.", "record_type": "PTR", "class": "IN"}
                ],
                "answers": [
                    {"name": "web._http._tcp.local.", "record_type": "A", "class": "IN", "ttl": 120, "rdata": "192.168.1.1"},
                    {"name": "web._http._tcp.local.", "record_type": "AAAA", "class": "IN", "ttl": 120, "rdata": "::1"}
                ],
                "authorities": [],
                "additionals": []
            }
        })
    }

    #[test]
    fn test_simple_filter() {
        let cfg = make_filter("message.message_type", Op::Eq, json!("response"));
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        assert!(engine.should_print(&test_entry()));
    }

    #[test]
    fn test_simple_filter_no_match() {
        let cfg = make_filter("message.message_type", Op::Eq, json!("query"));
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        assert!(!engine.should_print(&test_entry()));
    }

    #[test]
    fn test_array_wildcard_filter() {
        let cfg = make_filter("message.answers[*].record_type", Op::Eq, json!("A"));
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        assert!(engine.should_print(&test_entry()));
    }

    #[test]
    fn test_jq_filter() {
        let engine = FilterEngine::build(
            vec![],
            &[".message.message_type == \"response\"".into()],
        ).unwrap().unwrap();
        assert!(engine.should_print(&test_entry()));
    }

    #[test]
    fn test_jq_filter_complex() {
        let engine = FilterEngine::build(
            vec![],
            &[".message.answers | map(select(.record_type == \"A\")) | length > 0".into()],
        ).unwrap().unwrap();
        assert!(engine.should_print(&test_entry()));
    }

    #[test]
    fn test_no_filters_returns_none() {
        let result = FilterEngine::build(vec![], &[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_chain_and_semantics() {
        // Config 1: must be response
        let cfg1 = FilterConfig {
            mode: "any".into(),
            action: "show".into(),
            rule: vec![Rule {
                negate: false,
                condition: vec![Condition {
                    path: "message.message_type".into(),
                    op: Op::Eq,
                    value: json!("response"),
                }],
            }],
            chain: vec![],
        };
        // Config 2: must have A records
        let cfg2 = FilterConfig {
            mode: "any".into(),
            action: "show".into(),
            rule: vec![Rule {
                negate: false,
                condition: vec![Condition {
                    path: "message.answers[*].record_type".into(),
                    op: Op::Eq,
                    value: json!("A"),
                }],
            }],
            chain: vec![],
        };

        // Both pass -> print
        let engine = FilterEngine::build(vec![cfg1, cfg2], &[])
            .unwrap().unwrap();
        assert!(engine.should_print(&test_entry()));
    }

    #[test]
    fn test_chain_blocks_on_any_fail() {
        // Config 1: must be query (will fail for our test_entry which is response)
        let cfg1 = FilterConfig {
            mode: "any".into(),
            action: "show".into(),
            rule: vec![Rule {
                negate: false,
                condition: vec![Condition {
                    path: "message.message_type".into(),
                    op: Op::Eq,
                    value: json!("query"),
                }],
            }],
            chain: vec![],
        };
        // Config 2: has A records (would pass)
        let cfg2 = FilterConfig {
            mode: "any".into(),
            action: "show".into(),
            rule: vec![Rule {
                negate: false,
                condition: vec![Condition {
                    path: "message.answers[*].record_type".into(),
                    op: Op::Eq,
                    value: json!("A"),
                }],
            }],
            chain: vec![],
        };

        let engine = FilterEngine::build(vec![cfg1, cfg2], &[])
            .unwrap().unwrap();
        assert!(!engine.should_print(&test_entry()));
    }

    #[test]
    fn test_chain_hide_action() {
        // Config 1: show responses
        let cfg1 = FilterConfig {
            mode: "any".into(),
            action: "show".into(),
            rule: vec![Rule {
                negate: false,
                condition: vec![Condition {
                    path: "message.message_type".into(),
                    op: Op::Eq,
                    value: json!("response"),
                }],
            }],
            chain: vec![],
        };
        // Config 2: hide if from this source
        let cfg2 = FilterConfig {
            mode: "any".into(),
            action: "hide".into(),
            rule: vec![Rule {
                negate: false,
                condition: vec![Condition {
                    path: "source".into(),
                    op: Op::StartsWith,
                    value: json!("10.93.5.91"),
                }],
            }],
            chain: vec![],
        };

        let engine = FilterEngine::build(vec![cfg1, cfg2], &[])
            .unwrap().unwrap();
        // Response matches cfg1, but source matches cfg2's hide -> blocked
        assert!(!engine.should_print(&test_entry()));
    }

    // --- jq truthiness ---

    #[test]
    fn test_jq_returns_null_is_falsy() {
        let engine = FilterEngine::build(
            vec![], &["null".into()],
        ).unwrap().unwrap();
        assert!(!engine.should_print(&test_entry()));
    }

    #[test]
    fn test_jq_returns_false_is_falsy() {
        let engine = FilterEngine::build(
            vec![], &["false".into()],
        ).unwrap().unwrap();
        assert!(!engine.should_print(&test_entry()));
    }

    #[test]
    fn test_jq_returns_zero_is_truthy() {
        let engine = FilterEngine::build(
            vec![], &["0".into()],
        ).unwrap().unwrap();
        assert!(engine.should_print(&test_entry()));
    }

    #[test]
    fn test_jq_returns_empty_string_is_truthy() {
        let engine = FilterEngine::build(
            vec![], &[r#""""#.into()],
        ).unwrap().unwrap();
        assert!(engine.should_print(&test_entry()));
    }

    #[test]
    fn test_jq_syntax_error() {
        let result = FilterEngine::build(
            vec![], &["invalid[[[".into()],
        );
        assert!(result.is_err());
    }

    // --- Mode combinations ---

    #[test]
    fn test_mode_all_one_fails() {
        let cfg = FilterConfig {
            mode: "all".into(),
            action: "show".into(),
            rule: vec![
                Rule {
                    negate: false,
                    condition: vec![Condition {
                        path: "message.message_type".into(),
                        op: Op::Eq, value: json!("response"),
                    }],
                },
                Rule {
                    negate: false,
                    condition: vec![Condition {
                        path: "message.message_type".into(),
                        op: Op::Eq, value: json!("query"), // won't match
                    }],
                },
            ],
            chain: vec![],
        };
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        assert!(!engine.should_print(&test_entry()));
    }

    #[test]
    fn test_mode_all_both_pass() {
        let cfg = FilterConfig {
            mode: "all".into(),
            action: "show".into(),
            rule: vec![
                Rule {
                    negate: false,
                    condition: vec![Condition {
                        path: "message.message_type".into(),
                        op: Op::Eq, value: json!("response"),
                    }],
                },
                Rule {
                    negate: false,
                    condition: vec![Condition {
                        path: "message.authoritative".into(),
                        op: Op::Eq, value: json!(true),
                    }],
                },
            ],
            chain: vec![],
        };
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        assert!(engine.should_print(&test_entry()));
    }

    #[test]
    fn test_mode_any_all_fail() {
        let cfg = FilterConfig {
            mode: "any".into(),
            action: "show".into(),
            rule: vec![
                Rule {
                    negate: false,
                    condition: vec![Condition {
                        path: "message.message_type".into(),
                        op: Op::Eq, value: json!("query"),
                    }],
                },
                Rule {
                    negate: false,
                    condition: vec![Condition {
                        path: "interface".into(),
                        op: Op::Eq, value: json!("nonexistent"),
                    }],
                },
            ],
            chain: vec![],
        };
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        assert!(!engine.should_print(&test_entry()));
    }

    // --- Rule edge cases ---

    #[test]
    fn test_rule_with_no_conditions_matches_all() {
        let cfg = FilterConfig {
            mode: "any".into(),
            action: "show".into(),
            rule: vec![Rule { negate: false, condition: vec![] }],
            chain: vec![],
        };
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        assert!(engine.should_print(&test_entry()));
    }

    #[test]
    fn test_negate_with_matching_conditions() {
        let cfg = FilterConfig {
            mode: "any".into(),
            action: "show".into(),
            rule: vec![Rule {
                negate: true,
                condition: vec![Condition {
                    path: "message.message_type".into(),
                    op: Op::Eq, value: json!("response"),
                }],
            }],
            chain: vec![],
        };
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        // Conditions match, but negate inverts → rule doesn't match → not printed
        assert!(!engine.should_print(&test_entry()));
    }

    // --- Exists on missing field ---

    #[test]
    fn test_exists_true_on_missing_field() {
        let cfg = make_filter("nonexistent.field", Op::Exists, json!(true));
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        assert!(!engine.should_print(&test_entry()));
    }

    #[test]
    fn test_exists_false_on_missing_field() {
        let cfg = make_filter("nonexistent.field", Op::Exists, json!(false));
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        assert!(engine.should_print(&test_entry()));
    }

    // --- Mixed inline + jq ---

    #[test]
    fn test_config_passes_jq_fails() {
        let cfg = make_filter("message.message_type", Op::Eq, json!("response"));
        let engine = FilterEngine::build(
            vec![cfg],
            &["false".into()],
        ).unwrap().unwrap();
        assert!(!engine.should_print(&test_entry()));
    }

    // --- Empty chain link (no rules = pass-through) ---

    #[test]
    fn test_empty_config_is_pass_through() {
        let cfg = FilterConfig {
            mode: "any".into(),
            action: "show".into(),
            rule: vec![],
            chain: vec![],
        };
        // Config with no rules → chain link passes everything
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        assert!(engine.should_print(&test_entry()));
    }

    // --- Hide action on single config ---

    #[test]
    fn test_hide_matching() {
        let cfg = FilterConfig {
            mode: "any".into(),
            action: "hide".into(),
            rule: vec![Rule {
                negate: false,
                condition: vec![Condition {
                    path: "message.message_type".into(),
                    op: Op::Eq, value: json!("response"),
                }],
            }],
            chain: vec![],
        };
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        // Matches → hide → should NOT print
        assert!(!engine.should_print(&test_entry()));
    }

    #[test]
    fn test_hide_non_matching() {
        let cfg = FilterConfig {
            mode: "any".into(),
            action: "hide".into(),
            rule: vec![Rule {
                negate: false,
                condition: vec![Condition {
                    path: "message.message_type".into(),
                    op: Op::Eq, value: json!("query"),
                }],
            }],
            chain: vec![],
        };
        let engine = FilterEngine::build(vec![cfg], &[]).unwrap().unwrap();
        // Doesn't match → not hidden → SHOULD print
        assert!(engine.should_print(&test_entry()));
    }

    // --- load_configs with temp files ---

    #[test]
    fn test_load_configs_single_file() {
        let dir = std::env::temp_dir().join("dnssd-filter-test-1");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("filter.toml");
        std::fs::write(&path, r#"
            mode = "any"
            [[rule]]
            [[rule.condition]]
            path = "source"
            op = "eq"
            value = "test"
        "#).unwrap();

        let configs = load_configs(&[path.to_str().unwrap().to_string()]).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].rule.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_configs_with_chain() {
        let dir = std::env::temp_dir().join("dnssd-filter-test-2");
        std::fs::create_dir_all(&dir).unwrap();

        let child = dir.join("child.toml");
        std::fs::write(&child, r#"
            [[rule]]
            [[rule.condition]]
            path = "interface"
            op = "eq"
            value = "eth0"
        "#).unwrap();

        let parent = dir.join("parent.toml");
        std::fs::write(&parent, format!(r#"
            chain = ["{}"]
            [[rule]]
            [[rule.condition]]
            path = "source"
            op = "eq"
            value = "x"
        "#, child.to_str().unwrap())).unwrap();

        let configs = load_configs(&[parent.to_str().unwrap().to_string()]).unwrap();
        assert_eq!(configs.len(), 2); // parent + child
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_configs_circular_chain() {
        let dir = std::env::temp_dir().join("dnssd-filter-test-3");
        std::fs::create_dir_all(&dir).unwrap();

        let file_a = dir.join("a.toml");
        let file_b = dir.join("b.toml");

        std::fs::write(&file_a, format!(r#"chain = ["{}"]"#, file_b.to_str().unwrap())).unwrap();
        std::fs::write(&file_b, format!(r#"chain = ["{}"]"#, file_a.to_str().unwrap())).unwrap();

        let result = load_configs(&[file_a.to_str().unwrap().to_string()]);
        assert!(result.is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_configs_nonexistent_file() {
        let result = load_configs(&["/nonexistent/path.toml".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_configs_empty_list() {
        let configs = load_configs(&[]).unwrap();
        assert!(configs.is_empty());
    }
}
