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
}
