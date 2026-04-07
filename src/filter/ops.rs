use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

/// Operator for comparing a resolved value against an expected value.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    Ne,
    Contains,
    Icontains,
    StartsWith,
    EndsWith,
    Regex,
    Glob,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    Exists,
}

/// Evaluate an operator against a resolved JSON value and an expected value.
pub fn evaluate(op: &Op, resolved: &Value, expected: &Value) -> bool {
    match op {
        Op::Eq => resolved == expected,
        Op::Ne => resolved != expected,
        Op::Contains => match (resolved.as_str(), expected.as_str()) {
            (Some(haystack), Some(needle)) => haystack.contains(needle),
            _ => false,
        },
        Op::Icontains => match (resolved.as_str(), expected.as_str()) {
            (Some(haystack), Some(needle)) => {
                haystack.to_lowercase().contains(&needle.to_lowercase())
            }
            _ => false,
        },
        Op::StartsWith => match (resolved.as_str(), expected.as_str()) {
            (Some(s), Some(prefix)) => s.starts_with(prefix),
            _ => false,
        },
        Op::EndsWith => match (resolved.as_str(), expected.as_str()) {
            (Some(s), Some(suffix)) => s.ends_with(suffix),
            _ => false,
        },
        Op::Regex => match (resolved.as_str(), expected.as_str()) {
            (Some(s), Some(pattern)) => match Regex::new(pattern) {
                Ok(re) => re.is_match(s),
                Err(_) => false,
            },
            _ => false,
        },
        Op::Glob => match (resolved.as_str(), expected.as_str()) {
            (Some(s), Some(pattern)) => glob_match(pattern, s),
            _ => false,
        },
        Op::Gt => compare_numbers(resolved, expected, |a, b| a > b),
        Op::Gte => compare_numbers(resolved, expected, |a, b| a >= b),
        Op::Lt => compare_numbers(resolved, expected, |a, b| a < b),
        Op::Lte => compare_numbers(resolved, expected, |a, b| a <= b),
        Op::In => match expected.as_array() {
            Some(arr) => arr.iter().any(|v| v == resolved),
            None => false,
        },
        Op::Exists => match expected.as_bool() {
            Some(true) => !resolved.is_null(),
            Some(false) => resolved.is_null(),
            _ => false,
        },
    }
}

fn compare_numbers(a: &Value, b: &Value, cmp: impl Fn(f64, f64) -> bool) -> bool {
    let a_num = a.as_f64();
    let b_num = b.as_f64();
    match (a_num, b_num) {
        (Some(a), Some(b)) => cmp(a, b),
        _ => false,
    }
}

/// Simple glob matching: supports * (any chars) and ? (single char).
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_inner(&pat, &txt)
}

fn glob_match_inner(pat: &[char], txt: &[char]) -> bool {
    match (pat.first(), txt.first()) {
        (None, None) => true,
        (Some('*'), _) => {
            // Try matching rest of pattern with current text, or skip one text char
            glob_match_inner(&pat[1..], txt)
                || (!txt.is_empty() && glob_match_inner(pat, &txt[1..]))
        }
        (Some('?'), Some(_)) => glob_match_inner(&pat[1..], &txt[1..]),
        (Some(a), Some(b)) if a == b => glob_match_inner(&pat[1..], &txt[1..]),
        _ => false,
    }
}

/// Parse an inline filter expression like "path op value".
/// Returns (path, op, value) or an error message.
pub fn parse_inline(expr: &str) -> Result<(String, Op, Value), String> {
    let parts: Vec<&str> = expr.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err(format!("Invalid filter expression: '{}'. Expected: <path> <op> <value>", expr));
    }

    let path = parts[0].to_string();
    let op = match parts[1] {
        "eq" => Op::Eq,
        "ne" => Op::Ne,
        "contains" => Op::Contains,
        "icontains" => Op::Icontains,
        "starts_with" => Op::StartsWith,
        "ends_with" => Op::EndsWith,
        "regex" => Op::Regex,
        "glob" => Op::Glob,
        "gt" => Op::Gt,
        "gte" => Op::Gte,
        "lt" => Op::Lt,
        "lte" => Op::Lte,
        "in" => Op::In,
        "exists" => Op::Exists,
        other => return Err(format!("Unknown operator: '{}'", other)),
    };

    let value_str = parts[2];
    let value = match &op {
        Op::In => {
            // "A,AAAA,PTR" -> ["A", "AAAA", "PTR"]
            let items: Vec<Value> = value_str
                .split(',')
                .map(|s| parse_scalar(s.trim()))
                .collect();
            Value::Array(items)
        }
        Op::Exists => match value_str {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => return Err("exists operator expects 'true' or 'false'".into()),
        },
        Op::Gt | Op::Gte | Op::Lt | Op::Lte => {
            if let Ok(n) = value_str.parse::<f64>() {
                serde_json::json!(n)
            } else {
                return Err(format!("Expected number for operator '{}', got '{}'", parts[1], value_str));
            }
        }
        _ => parse_scalar(value_str),
    };

    Ok((path, op, value))
}

/// Parse a string into the most appropriate JSON scalar.
fn parse_scalar(s: &str) -> Value {
    if s == "true" {
        Value::Bool(true)
    } else if s == "false" {
        Value::Bool(false)
    } else if s == "null" {
        Value::Null
    } else if let Ok(n) = s.parse::<i64>() {
        Value::Number(n.into())
    } else if let Ok(n) = s.parse::<f64>() {
        serde_json::json!(n)
    } else {
        Value::String(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_eq() {
        assert!(evaluate(&Op::Eq, &json!("hello"), &json!("hello")));
        assert!(!evaluate(&Op::Eq, &json!("hello"), &json!("world")));
    }

    #[test]
    fn test_contains() {
        assert!(evaluate(&Op::Contains, &json!("_http._tcp.local."), &json!("_http")));
    }

    #[test]
    fn test_glob() {
        assert!(evaluate(&Op::Glob, &json!("_http._tcp.local."), &json!("*._tcp.local.")));
        assert!(!evaluate(&Op::Glob, &json!("_http._udp.local."), &json!("*._tcp.local.")));
    }

    #[test]
    fn test_in_op() {
        let arr = json!(["A", "AAAA"]);
        assert!(evaluate(&Op::In, &json!("A"), &arr));
        assert!(!evaluate(&Op::In, &json!("PTR"), &arr));
    }

    #[test]
    fn test_numeric() {
        assert!(evaluate(&Op::Gt, &json!(200), &json!(100)));
        assert!(!evaluate(&Op::Gt, &json!(50), &json!(100)));
    }

    #[test]
    fn test_parse_inline() {
        let (path, _op, value) = parse_inline("message.message_type eq response").unwrap();
        assert_eq!(path, "message.message_type");
        assert_eq!(value, json!("response"));
    }

    #[test]
    fn test_parse_inline_in() {
        let (_, _op, value) = parse_inline("message.answers[*].record_type in A,AAAA").unwrap();
        assert_eq!(value, json!(["A", "AAAA"]));
    }
}
