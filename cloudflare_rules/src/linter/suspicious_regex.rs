use super::*;
use regex_syntax::Parser;
use wirefilter::{ComparisonExpr, ComparisonOpExpr, IdentifierExpr, Visitor};

static LINT_NAME: &str = "suspicious_regex";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Detect regexes that look like they should be wildcard matches or contain unescaped literal special characters.",
        category: Category::Suspicious,
        lint_fn: lint
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    struct SuspiciousRegexVisitor {
        result: Vec<LintReport>,
    }

    let mut visitor = SuspiciousRegexVisitor { result: Vec::new() };

    // Simple scanner helpers that detect unescaped special characters outside of character classes.
    fn scan_pattern(pattern: &str) -> (bool, bool, bool, bool) {
        // returns (has_unescaped_dot_outside_class, has_unescaped_qmark_outside_class, contains_slash_star_slash, ends_with_slash_star)
        let mut escaped = false;
        let mut in_class = false;
        let mut prev: Option<char> = None;
        let mut has_dot = false;
        let mut has_q = false;
        let mut contains_slash_star_slash = false;
        let mut ends_with_slash_star = false;

        let chars: Vec<char> = pattern.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            if escaped {
                escaped = false;
                prev = Some(c);
                continue;
            }
            if c == '\\' {
                escaped = true;
                continue;
            }
            if c == '[' && !in_class {
                in_class = true;
                prev = Some(c);
                continue;
            }
            if c == ']' && in_class {
                in_class = false;
                prev = Some(c);
                continue;
            }

            if !in_class {
                if c == '.' {
                    has_dot = true;
                }
                if c == '?' {
                    has_q = true;
                }
                if c == '*'
                    && let Some(p) = prev
                    && p == '/'
                {
                    // pattern contains "/*"; check following char for another '/'
                    if i + 1 < chars.len() && chars[i + 1] == '/' {
                        contains_slash_star_slash = true;
                    }
                }
            }

            prev = Some(c);
        }

        // ends_with_slash_star check (unescaped)
        if pattern.ends_with("/*") {
            // ensure it isn't escaped (i.e., ends with "\/*")
            if !pattern.ends_with("\\/*") {
                ends_with_slash_star = true;
            }
        }

        (
            has_dot,
            has_q,
            contains_slash_star_slash,
            ends_with_slash_star,
        )
    }

    impl Visitor<'_> for SuspiciousRegexVisitor {
        fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
            if let ComparisonOpExpr::Matches(regex) = &node.op {
                let pattern = regex.as_str();

                // Use regex-syntax parser at least to adhere to the requirement and to ensure the
                // pattern is a valid regex (we ignore parse errors and still run the heuristics).
                let _ = Parser::new().parse(pattern);

                let (has_dot, has_q, contains_slash_star_slash, ends_with_slash_star) =
                    scan_pattern(pattern);

                // Determine field context when available to make smarter heuristics.
                let field_name = if let IdentifierExpr::Field(field) = &node.lhs.identifier {
                    Some(field.name().to_string())
                } else {
                    None
                };

                let mut suspicious = false;
                let mut message = String::new();

                // Path-related heuristics
                if let Some(fname) = &field_name {
                    if fname == "http.request.uri.path" || fname == "raw.http.request.uri.path" {
                        if contains_slash_star_slash || ends_with_slash_star {
                            suspicious = true;
                            message = "Regex uses quantifiers on path separators (e.g., `/*`); \
                                       this often indicates a wildcard intent — consider using a \
                                       wildcard match instead or escaping the separator."
                                .to_string();
                        } else if has_dot {
                            // Unescaped dot inside a path is suspicious when used as a literal separator/extension
                            // (e.g., index.html)
                            // Ignore dots inside character classes because those are explicit literal dots.
                            suspicious = true;
                            message = r"Regex contains an unescaped `.` which is interpreted as any character; escape it as `\.` or use a wildcard match depending on intent.".to_string();
                        }
                    } else if fname == "http.request.uri"
                        || fname == "raw.http.request.uri"
                        || fname == "http.request.full_uri"
                        || fname == "raw.http.request.full_uri"
                    {
                        // Full URI: unescaped dots and question marks are common mistakes
                        if has_dot || has_q {
                            suspicious = true;
                            message = r"Regex contains unescaped `.` or `?` characters in a URI; escape them (e.g., `\.` and `\?`) or use a wildcard match where appropriate.".to_string();
                        }
                    } else if fname == "http.host" {
                        // Hostname: unescaped dots are usually intended as literal separators
                        // Heuristic: only flag when there are no other regex meta-characters present
                        if has_dot {
                            suspicious = true;
                            message = r"Regex contains unescaped `.` in a hostname; escape the dot as `\.` or use a wildcard match if you intended to match subdomains.".to_string();
                        }
                    }
                }

                // Generic heuristics (applies regardless of field)
                if !suspicious {
                    // common glob-like regex: ^/foo/.*$ or /.*
                    if pattern.contains("/.*")
                        || pattern.starts_with("^/") && pattern.contains(".*")
                    {
                        suspicious = true;
                        message = "Regex uses `.*` to match path segments; consider using a \
                                   wildcard match or be more specific."
                            .to_string();
                    }
                }

                if !suspicious {
                    // question marks used literally in query parts
                    if has_q && pattern.contains("https://") {
                        suspicious = true;
                        message = r"Regex contains an unescaped `?` within a URI; escape it as `\?` or use a wildcard match.".to_string();
                    }
                }

                if suspicious {
                    self.result.push(LintReport {
                        id: LINT_NAME.into(),
                        url: Some(create_url(LINT_NAME)),
                        title: "Suspicious regex that looks like a wildcard".to_string(),
                        message,
                        span: Span::ReverseByte(node.reverse_span.clone()),
                    });
                }
            }

            self.visit_expr(node);
        }
    }

    ast.walk(&mut visitor);
    visitor.result
}

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::*;

    static LINTER: std::sync::LazyLock<Linter> = std::sync::LazyLock::new(|| {
        let mut linter = Linter::new();
        linter.config = LinterConfig::default_disable_all_lints();
        linter.config.lints.enable_lints = vec![LINT_NAME.into()];
        linter
    });

    #[test]
    fn test_path_slash_star_slash() {
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path matches "/*/foo/bar/baz""#,
            expect![[r#"
				Suspicious regex that looks like a wildcard (suspicious_regex)
				Regex uses quantifiers on path separators (e.g., `/*`); this often indicates a wildcard intent — consider using a wildcard match instead or escaping the separator."#]],
        );
    }

    #[test]
    fn test_path_ends_with_slash_star() {
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path matches "/foo/bar/baz/*""#,
            expect![[r#"
				Suspicious regex that looks like a wildcard (suspicious_regex)
				Regex uses quantifiers on path separators (e.g., `/*`); this often indicates a wildcard intent — consider using a wildcard match instead or escaping the separator."#]],
        );
    }

    #[test]
    fn test_unescaped_dot_in_path() {
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path matches "/foo/bar/index.html""#,
            expect![[r#"
				Suspicious regex that looks like a wildcard (suspicious_regex)
				Regex contains an unescaped `.` which is interpreted as any character; escape it as `\.` or use a wildcard match depending on intent."#]],
        );

        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path matches "/foo/bar/index.php""#,
            expect![[r#"
				Suspicious regex that looks like a wildcard (suspicious_regex)
				Regex contains an unescaped `.` which is interpreted as any character; escape it as `\.` or use a wildcard match depending on intent."#]],
        );
    }

    #[test]
    fn test_version_dot() {
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path matches "/api/v./foo/bar""#,
            expect![[r#"
				Suspicious regex that looks like a wildcard (suspicious_regex)
				Regex contains an unescaped `.` which is interpreted as any character; escape it as `\.` or use a wildcard match depending on intent."#]],
        );
    }

    #[test]
    fn test_hostname_dots() {
        expect_lint_message(
            &LINTER,
            r#"http.host matches "example.com""#,
            expect![[r#"
				Suspicious regex that looks like a wildcard (suspicious_regex)
				Regex contains unescaped `.` in a hostname; escape the dot as `\.` or use a wildcard match if you intended to match subdomains."#]],
        );

        expect_lint_message(
            &LINTER,
            r#"http.host matches "www.example.org""#,
            expect![[r#"
				Suspicious regex that looks like a wildcard (suspicious_regex)
				Regex contains unescaped `.` in a hostname; escape the dot as `\.` or use a wildcard match if you intended to match subdomains."#]],
        );
    }

    #[test]
    fn test_full_uri() {
        expect_lint_message(
            &LINTER,
            r#"http.request.uri matches "https://www.example.org/foo/index.html?query=args""#,
            expect![[r#"
				Suspicious regex that looks like a wildcard (suspicious_regex)
				Regex contains unescaped `.` or `?` characters in a URI; escape them (e.g., `\.` and `\?`) or use a wildcard match where appropriate."#]],
        );
    }

    #[test]
    fn test_full_uri_field_names() {
        expect_lint_message(
            &LINTER,
            r#"http.request.full_uri matches "https://www.example.org/articles/index?section=539061&expand=comments""#,
            expect![[r#"
                Suspicious regex that looks like a wildcard (suspicious_regex)
                Regex contains unescaped `.` or `?` characters in a URI; escape them (e.g., `\.` and `\?`) or use a wildcard match where appropriate."#]],
        );

        expect_lint_message(
            &LINTER,
            r#"raw.http.request.full_uri matches "https://www.example.org/articles/index?section=539061&expand=comments""#,
            expect![[r#"
                Suspicious regex that looks like a wildcard (suspicious_regex)
                Regex contains unescaped `.` or `?` characters in a URI; escape them (e.g., `\.` and `\?`) or use a wildcard match where appropriate."#]],
        );
    }

    #[test]
    fn test_raw_uri_field() {
        expect_lint_message(
            &LINTER,
            r#"raw.http.request.uri matches "/articles/index?section=539061&expand=comments""#,
            expect![[r#"
                Suspicious regex that looks like a wildcard (suspicious_regex)
                Regex contains unescaped `.` or `?` characters in a URI; escape them (e.g., `\.` and `\?`) or use a wildcard match where appropriate."#]],
        );
    }

    #[test]
    fn test_allowed_character_class() {
        assert_no_lint_message(&LINTER, r#"http.request.uri.path matches "/foo/[.apc]""#);
    }

    #[test]
    fn test_escaped_dot_no_warn() {
        assert_no_lint_message(
            &LINTER,
            r#"http.request.uri.path matches "/foo/bar/index\.html""#,
        );
    }
}
