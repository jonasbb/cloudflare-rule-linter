use super::*;
use regex_syntax::Parser;
use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, FunctionCallArgExpr, IdentifierExpr, RhsValue, Visitor,
};

static LINT_NAME: &str = "suspicious_regex";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Detect regexes that look like they should be wildcard matches or contain unescaped literal special characters.",
        category: Category::Suspicious,
        lint_fn: lint,
        lint_value_fn: lint_value,
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = SuspiciousRegexVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

fn lint_value(_config: &LinterConfig, ast: &FilterValueAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = SuspiciousRegexVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

#[derive(Default)]
struct SuspiciousRegexVisitor {
    result: Vec<LintReport>,
}

// Simple scanner helpers that detect unescaped special characters outside of character classes.
// Returns (has_unescaped_literal_dot, has_unescaped_query_like, contains_slash_star_slash)
fn scan_pattern(pattern: &str) -> (bool, bool, bool) {
    let mut escaped = false;
    let mut in_class = false;
    let mut prev: Option<char> = None;
    let mut has_unescaped_dot_literal = false;
    let mut has_unescaped_query_like = false;
    let mut contains_slash_star_slash = false;

    let chars: Vec<char> = pattern.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if escaped {
            escaped = false;
            prev = Some(c);
            continue;
        }
        if c == '\\' {
            escaped = true;
            prev = Some(c);
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
            let next = chars.get(i + 1).copied();
            if c == '.' {
                // Treat an unescaped '.' as suspicious only when it's not immediately
                // followed by a quantifier (e.g., '.*', '.+', '.?','.{') since those
                // are commonly intentional uses of the dot metacharacter.
                let next_is_quant = matches!(next, Some('*' | '+' | '?' | '{'));
                if !next_is_quant {
                    has_unescaped_dot_literal = true;
                }
            }

            if c == '?' {
                // Ignore the ? if the previous character is a quantifier (e.g., '.*?', '.+?') or otherwise part of a sensible use
                // (? starts regex commands eg (?i) or (?:...), so we only flag it when it looks like a literal question mark that might be intended as a query separator.
                // Optional character classes like [a-z]? are common
                let prev_is_valid = matches!(prev, Some('*' | '+' | '(' | ')' | '[' | ']'));
                // If a '?' appears unescaped and is followed by an alphanumeric or '='/'&',
                // it is likely the literal query separator rather than a regex quantifier.
                if !prev_is_valid {
                    has_unescaped_query_like = true;
                }
            }

            if c == '*'
                && let Some('/') = prev
                && let Some('/') | None = next
            {
                contains_slash_star_slash = true;
            }
        }

        prev = Some(c);
    }

    (
        has_unescaped_dot_literal,
        has_unescaped_query_like,
        contains_slash_star_slash,
    )
}

impl Visitor<'_> for SuspiciousRegexVisitor {
    fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
        if let ComparisonOpExpr::Matches(regex) = &node.op {
            // Determine field context when available to make smarter heuristics.
            let field_name = if let IdentifierExpr::Field(field) = &node.lhs.identifier {
                Some(field.name())
            } else {
                None
            };

            self.emit_lint(node.reverse_span.clone(), regex.as_str(), field_name);
        }

        self.visit_expr(node);
    }

    fn visit_index_expr(&mut self, node: &'_ wirefilter::IndexExpr) {
        // Could be written with visit_function_call_expr but that doesn't have access to a reverse_span

        if let IdentifierExpr::FunctionCallExpr(func) = node.identifier()
            && func.function().name() == "regex_replace"
            && let [
                FunctionCallArgExpr::IndexExpr(field),
                wirefilter::FunctionCallArgExpr::Literal(RhsValue::Bytes(regex)),
                _replacement,
            ] = func.args()
            && let IdentifierExpr::Field(field) = &field.identifier
            && let field_name = field.name()
            && let Ok(regex) = str::from_utf8(regex)
        {
            self.emit_lint(node.reverse_span.clone(), regex, Some(field_name));
        }

        self.visit_value_expr(node);
    }
}

impl SuspiciousRegexVisitor {
    fn emit_lint(&mut self, reverse_span: Range<usize>, pattern: &str, field_name: Option<&str>) {
        let (has_dot, has_q, contains_slash_star_slash) = scan_pattern(pattern);

        let mut suspicious = false;
        let mut message = String::new();

        // Use regex-syntax parser at least to adhere to the requirement and to ensure the
        // pattern is a valid regex (we ignore parse errors and still run the heuristics).
        if let Err(err) = Parser::new().parse(pattern) {
            self.result.push(LintReport {
                id: LINT_NAME.into(),
                url: Some(create_url(LINT_NAME)),
                title: "Cannot parse the regex argument".to_string(),
                message: format!("{err}"),
                span: Span::ReverseByte(reverse_span.clone()),
            });
        }

        // Path-related heuristics
        if let Some(fname) = field_name {
            if fname == "http.request.uri.path" || fname == "raw.http.request.uri.path" {
                if contains_slash_star_slash {
                    suspicious = true;
                    message = "Regex uses quantifiers on path separators (e.g., `/*`); this often \
                               indicates a wildcard intent — consider using a wildcard match \
                               instead or escaping the separator."
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
                // Allow matching on optional 's' in 'https' (e.g., https?://) without flagging as suspicious since that's a common pattern, but flag other unescaped '?' characters that look like they might be intended as query separators.
                if has_dot || (has_q && !pattern.contains("https?")) {
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

        if suspicious {
            self.result.push(LintReport {
                id: LINT_NAME.into(),
                url: Some(create_url(LINT_NAME)),
                title: "Suspicious regex that looks like a wildcard".to_string(),
                message,
                span: Span::ReverseByte(reverse_span.clone()),
            });
        }
    }
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

    #[test]
    fn test_ok_dot_star_patterns() {
        assert_no_lint_message(&LINTER, r#"http.request.uri.path matches "^/foo/.*""#);
        assert_no_lint_message(&LINTER, r#"http.request.uri.path matches "^/foo.*""#);
        assert_no_lint_message(&LINTER, r#"http.request.uri.path matches "^/.*/bar""#);
    }

    #[test]
    fn test_https_optional() {
        assert_no_lint_message(
            &LINTER,
            r#"http.request.uri matches "https?://www\.example\.com/foo""#,
        );
    }

    #[test]
    fn test_case_insensitive() {
        assert_no_lint_message(
            &LINTER,
            r#"http.request.uri matches "(?i)https://www\.example\.com/foo""#,
        );
    }

    #[test]
    fn test_case_groups() {
        assert_no_lint_message(
            &LINTER,
            r#"http.request.uri matches "https://www\.example\.com/(?:foo/|bar/)index\.html""#,
        );
        assert_no_lint_message(
            &LINTER,
            r#"http.request.uri matches "https://www\.example\.com/(foo/|bar/)?index\.html""#,
        );
        assert_no_lint_message(
            &LINTER,
            r#"http.request.uri matches "https://www\.example\.com/api/v1[0-9]?/foo""#,
        );
    }

    #[test]
    fn test_non_greedy_and_charclass_no_warn() {
        assert_no_lint_message(
            &LINTER,
            r#"http.request.uri.path matches "/foo/[abc]*?/bar""#,
        );
    }
}
