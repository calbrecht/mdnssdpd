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

    // --- Operators ---

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

    #[test]
    fn test_exists_with_non_bool_expected() {
        assert!(!evaluate(&Op::Exists, &json!("x"), &json!("not_a_bool")));
        assert!(!evaluate(&Op::Exists, &json!("x"), &json!(42)));
    }
}
