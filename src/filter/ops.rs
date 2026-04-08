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

    // --- Untested operators ---

    #[test]
    fn test_ne() {
        assert!(evaluate(&Op::Ne, &json!("hello"), &json!("world")));
        assert!(!evaluate(&Op::Ne, &json!("hello"), &json!("hello")));
        assert!(evaluate(&Op::Ne, &json!(1), &json!(2)));
        assert!(!evaluate(&Op::Ne, &json!(true), &json!(true)));
    }

    #[test]
    fn test_icontains() {
        assert!(evaluate(&Op::Icontains, &json!("Hello World"), &json!("hello")));
        assert!(evaluate(&Op::Icontains, &json!("HELLO"), &json!("hello")));
        assert!(!evaluate(&Op::Icontains, &json!("hello"), &json!("xyz")));
    }

    #[test]
    fn test_starts_with() {
        assert!(evaluate(&Op::StartsWith, &json!("_http._tcp.local."), &json!("_http")));
        assert!(!evaluate(&Op::StartsWith, &json!("_http._tcp.local."), &json!("_tcp")));
    }

    #[test]
    fn test_ends_with() {
        assert!(evaluate(&Op::EndsWith, &json!("_http._tcp.local."), &json!(".local.")));
        assert!(!evaluate(&Op::EndsWith, &json!("_http._tcp.local."), &json!("_http")));
    }

    #[test]
    fn test_regex() {
        assert!(evaluate(&Op::Regex, &json!("_airplay._tcp.local."), &json!("_(airplay|raop)")));
        assert!(!evaluate(&Op::Regex, &json!("_http._tcp.local."), &json!("_(airplay|raop)")));
    }

    #[test]
    fn test_regex_invalid_pattern() {
        // Invalid regex should return false, not panic
        assert!(!evaluate(&Op::Regex, &json!("test"), &json!("[invalid")));
    }

    #[test]
    fn test_gte() {
        assert!(evaluate(&Op::Gte, &json!(100), &json!(100)));
        assert!(evaluate(&Op::Gte, &json!(101), &json!(100)));
        assert!(!evaluate(&Op::Gte, &json!(99), &json!(100)));
    }

    #[test]
    fn test_lt() {
        assert!(evaluate(&Op::Lt, &json!(50), &json!(100)));
        assert!(!evaluate(&Op::Lt, &json!(100), &json!(100)));
        assert!(!evaluate(&Op::Lt, &json!(150), &json!(100)));
    }

    #[test]
    fn test_lte() {
        assert!(evaluate(&Op::Lte, &json!(100), &json!(100)));
        assert!(evaluate(&Op::Lte, &json!(99), &json!(100)));
        assert!(!evaluate(&Op::Lte, &json!(101), &json!(100)));
    }

    #[test]
    fn test_exists_true() {
        assert!(evaluate(&Op::Exists, &json!("something"), &json!(true)));
        assert!(evaluate(&Op::Exists, &json!(42), &json!(true)));
        assert!(!evaluate(&Op::Exists, &json!(null), &json!(true)));
    }

    #[test]
    fn test_exists_false() {
        assert!(evaluate(&Op::Exists, &json!(null), &json!(false)));
        assert!(!evaluate(&Op::Exists, &json!("something"), &json!(false)));
    }

    // --- Type mismatch edge cases ---

    #[test]
    fn test_string_ops_on_non_strings() {
        assert!(!evaluate(&Op::Contains, &json!(123), &json!("1")));
        assert!(!evaluate(&Op::Icontains, &json!(null), &json!("x")));
        assert!(!evaluate(&Op::StartsWith, &json!(true), &json!("t")));
        assert!(!evaluate(&Op::EndsWith, &json!([1,2]), &json!("2")));
        assert!(!evaluate(&Op::Regex, &json!(42), &json!("4")));
        assert!(!evaluate(&Op::Glob, &json!(null), &json!("*")));
    }

    #[test]
    fn test_numeric_ops_on_non_numbers() {
        assert!(!evaluate(&Op::Gt, &json!("big"), &json!("small")));
        assert!(!evaluate(&Op::Lt, &json!(null), &json!(0)));
    }

    #[test]
    fn test_in_with_non_array() {
        assert!(!evaluate(&Op::In, &json!("A"), &json!("A")));
        assert!(!evaluate(&Op::In, &json!("A"), &json!(null)));
    }

    // --- Glob edge cases ---

    #[test]
    fn test_glob_literal() {
        assert!(evaluate(&Op::Glob, &json!("exact"), &json!("exact")));
        assert!(!evaluate(&Op::Glob, &json!("exact"), &json!("other")));
    }

    #[test]
    fn test_glob_question_mark() {
        assert!(evaluate(&Op::Glob, &json!("abc"), &json!("a?c")));
        assert!(!evaluate(&Op::Glob, &json!("abbc"), &json!("a?c")));
    }

    #[test]
    fn test_glob_star_only() {
        assert!(evaluate(&Op::Glob, &json!("anything"), &json!("*")));
        assert!(evaluate(&Op::Glob, &json!(""), &json!("*")));
    }

    #[test]
    fn test_glob_empty() {
        assert!(evaluate(&Op::Glob, &json!(""), &json!("")));
        assert!(!evaluate(&Op::Glob, &json!("x"), &json!("")));
    }

    // --- parse_inline edge cases ---

    #[test]
    fn test_parse_inline_too_few_parts() {
        assert!(parse_inline("only_path").is_err());
        assert!(parse_inline("path op").is_err());
    }

    #[test]
    fn test_parse_inline_unknown_op() {
        assert!(parse_inline("path unknown_op value").is_err());
    }

    #[test]
    fn test_parse_inline_numeric_error() {
        assert!(parse_inline("path gt not_a_number").is_err());
    }

    #[test]
    fn test_parse_inline_exists_invalid() {
        assert!(parse_inline("path exists maybe").is_err());
    }

    #[test]
    fn test_parse_inline_exists_valid() {
        let (_, _, v) = parse_inline("path exists true").unwrap();
        assert_eq!(v, json!(true));
        let (_, _, v) = parse_inline("path exists false").unwrap();
        assert_eq!(v, json!(false));
    }

    #[test]
    fn test_parse_scalar_types() {
        assert_eq!(parse_scalar("true"), json!(true));
        assert_eq!(parse_scalar("false"), json!(false));
        assert_eq!(parse_scalar("null"), json!(null));
        assert_eq!(parse_scalar("42"), json!(42));
        assert_eq!(parse_scalar("3.14"), json!(3.14));
        assert_eq!(parse_scalar("hello"), json!("hello"));
    }

    #[test]
    fn test_exists_with_non_bool_expected() {
        // Exists with a string expected value → false (line 70)
        assert!(!evaluate(&Op::Exists, &json!("x"), &json!("not_a_bool")));
        assert!(!evaluate(&Op::Exists, &json!("x"), &json!(42)));
    }

    #[test]
    fn test_parse_inline_numeric_success() {
        // Exercises the json!(n) path (line 149) in parse_inline
        let (path, _, value) = parse_inline("packet_size gte 200").unwrap();
        assert_eq!(path, "packet_size");
        assert_eq!(value, json!(200.0));
    }
}
