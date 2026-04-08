use serde_json::Value;

/// A segment in a path expression.
#[derive(Debug, Clone)]
pub enum PathSegment {
    /// A named field, e.g. "message"
    Field(String),
    /// Array wildcard [*] — iterate all elements
    ArrayWildcard,
}

/// Parse a dot-notation path like "message.questions[*].name" into segments.
pub fn parse_path(path: &str) -> Vec<PathSegment> {
    let mut segments = Vec::new();
    for part in path.split('.') {
        if part.ends_with("[*]") {
            let field = &part[..part.len() - 3];
            if !field.is_empty() {
                segments.push(PathSegment::Field(field.to_string()));
            }
            segments.push(PathSegment::ArrayWildcard);
        } else if !part.is_empty() {
            segments.push(PathSegment::Field(part.to_string()));
        }
    }
    segments
}

/// Resolve a path expression against a JSON value.
/// Returns all values matching the path (multiple for array wildcards).
pub fn resolve<'a>(value: &'a Value, segments: &[PathSegment]) -> Vec<&'a Value> {
    let mut current = vec![value];

    for seg in segments {
        let mut next = Vec::new();
        match seg {
            PathSegment::Field(name) => {
                for v in &current {
                    if let Some(child) = v.get(name.as_str()) {
                        next.push(child);
                    }
                }
            }
            PathSegment::ArrayWildcard => {
                for v in &current {
                    if let Some(arr) = v.as_array() {
                        next.extend(arr.iter());
                    }
                }
            }
        }
        current = next;
    }

    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_simple() {
        let segs = parse_path("message.opcode");
        assert_eq!(segs.len(), 2);
        assert!(matches!(&segs[0], PathSegment::Field(s) if s == "message"));
        assert!(matches!(&segs[1], PathSegment::Field(s) if s == "opcode"));
    }

    #[test]
    fn test_parse_wildcard() {
        let segs = parse_path("message.questions[*].name");
        assert_eq!(segs.len(), 4);
        assert!(matches!(&segs[2], PathSegment::ArrayWildcard));
    }

    #[test]
    fn test_resolve_nested() {
        let v = json!({"message": {"opcode": "Query"}});
        let segs = parse_path("message.opcode");
        let res = resolve(&v, &segs);
        assert_eq!(res, vec![&json!("Query")]);
    }

    #[test]
    fn test_resolve_wildcard() {
        let v = json!({"message": {"questions": [{"name": "a"}, {"name": "b"}]}});
        let segs = parse_path("message.questions[*].name");
        let res = resolve(&v, &segs);
        assert_eq!(res, vec![&json!("a"), &json!("b")]);
    }

    // --- parse_path edge cases ---

    #[test]
    fn test_parse_empty() {
        assert_eq!(parse_path("").len(), 0);
    }

    #[test]
    fn test_parse_double_dots() {
        // "message..opcode" → skips empty segments
        let segs = parse_path("message..opcode");
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn test_parse_only_wildcard() {
        let segs = parse_path("[*]");
        assert_eq!(segs.len(), 1);
        assert!(matches!(&segs[0], PathSegment::ArrayWildcard));
    }

    #[test]
    fn test_parse_nested_wildcards() {
        let segs = parse_path("a[*].b[*].c");
        assert_eq!(segs.len(), 5);
        assert!(matches!(&segs[0], PathSegment::Field(s) if s == "a"));
        assert!(matches!(&segs[1], PathSegment::ArrayWildcard));
        assert!(matches!(&segs[2], PathSegment::Field(s) if s == "b"));
        assert!(matches!(&segs[3], PathSegment::ArrayWildcard));
        assert!(matches!(&segs[4], PathSegment::Field(s) if s == "c"));
    }

    #[test]
    fn test_parse_underscores_and_numbers() {
        let segs = parse_path("dns_class.record_2.ttl_value");
        assert_eq!(segs.len(), 3);
    }

    // --- resolve edge cases ---

    #[test]
    fn test_resolve_empty_path() {
        let v = json!({"x": 1});
        let res = resolve(&v, &[]);
        assert_eq!(res, vec![&json!({"x": 1})]);
    }

    #[test]
    fn test_resolve_missing_field() {
        let v = json!({"message": {"opcode": "Query"}});
        let segs = parse_path("message.nonexistent.deep");
        let res = resolve(&v, &segs);
        assert!(res.is_empty());
    }

    #[test]
    fn test_resolve_non_object_intermediate() {
        let v = json!({"message": "just_a_string"});
        let segs = parse_path("message.opcode");
        let res = resolve(&v, &segs);
        assert!(res.is_empty());
    }

    #[test]
    fn test_resolve_wildcard_on_non_array() {
        let v = json!({"items": "not_an_array"});
        let segs = parse_path("items[*].name");
        let res = resolve(&v, &segs);
        assert!(res.is_empty());
    }

    #[test]
    fn test_resolve_wildcard_on_empty_array() {
        let v = json!({"items": []});
        let segs = parse_path("items[*].name");
        let res = resolve(&v, &segs);
        assert!(res.is_empty());
    }

    #[test]
    fn test_resolve_deep_nesting() {
        let v = json!({"a": {"b": {"c": {"d": {"e": {"f": 42}}}}}});
        let segs = parse_path("a.b.c.d.e.f");
        let res = resolve(&v, &segs);
        assert_eq!(res, vec![&json!(42)]);
    }

    #[test]
    fn test_resolve_null_intermediate() {
        let v = json!({"a": null});
        let segs = parse_path("a.b");
        let res = resolve(&v, &segs);
        assert!(res.is_empty());
    }

    #[test]
    fn test_resolve_null_leaf() {
        let v = json!({"a": null});
        let segs = parse_path("a");
        let res = resolve(&v, &segs);
        assert_eq!(res, vec![&json!(null)]);
    }

    #[test]
    fn test_resolve_nested_wildcards() {
        let v = json!({"groups": [
            {"items": [{"val": 1}, {"val": 2}]},
            {"items": [{"val": 3}]}
        ]});
        let segs = parse_path("groups[*].items[*].val");
        let res = resolve(&v, &segs);
        assert_eq!(res, vec![&json!(1), &json!(2), &json!(3)]);
    }
}
