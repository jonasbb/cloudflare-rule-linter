use super::*;
use wirefilter::{ComparisonExpr, ComparisonOpExpr, OrderingOp, RhsValue, RhsValues, Visitor};

static LINT_NAME: &str = "regex_string_literal";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Detect regex-looking string literals used with non-regex comparison operators.",
        category: Category::Correctness,
        lint_fn: lint,
        lint_value_fn: lint_value,
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = RegexStringLiteralVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

fn lint_value(_config: &LinterConfig, ast: &FilterValueAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = RegexStringLiteralVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

#[derive(Default)]
struct RegexStringLiteralVisitor {
    result: Vec<LintReport>,
}

impl Visitor<'_> for RegexStringLiteralVisitor {
    fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
        let has_regex_literal = match &node.op {
            ComparisonOpExpr::Ordering {
                op: OrderingOp::Equal | OrderingOp::NotEqual,
                rhs: RhsValue::Bytes(bytes),
            } => string_looks_like_regex(bytes),
            ComparisonOpExpr::Contains(bytes) => string_looks_like_regex(bytes),
            ComparisonOpExpr::Wildcard(pattern) => string_looks_like_regex(pattern.pattern()),
            ComparisonOpExpr::StrictWildcard(pattern) => string_looks_like_regex(pattern.pattern()),
            ComparisonOpExpr::OneOf(RhsValues::Bytes(items)) => {
                items.iter().any(|item| string_looks_like_regex(item))
            }
            _ => false,
        };

        if has_regex_literal {
            self.result.push(LintReport {
                id: LINT_NAME.into(),
                url: Some(create_url(LINT_NAME)),
                title: "Found regex syntax with a non-regex comparison operator".into(),
                message: "This string contains regex syntax, but only `matches` interprets \
                          regular expressions. Use `matches` or remove the regex syntax."
                    .to_string(),
                span: Span::ReverseByte(node.reverse_span.clone()),
            });
        }

        self.visit_expr(node);
    }
}

fn string_looks_like_regex(bytes: &[u8]) -> bool {
    let Ok(pattern) = std::str::from_utf8(bytes) else {
        return false;
    };
    has_anchor(pattern) || has_inline_flags(pattern) || has_posix_character_class(pattern)
}

fn has_anchor(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    if bytes.first() == Some(&b'^') {
        return true;
    }
    bytes.last() == Some(&b'$') && !is_escaped(bytes, bytes.len() - 1)
}

fn has_inline_flags(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut index = 0;
    while index + 2 < bytes.len() {
        if bytes[index..].starts_with(b"(?") && !is_escaped(bytes, index) {
            let mut cursor = index + 2;
            let mut has_flag = false;
            while let Some(&byte) = bytes.get(cursor) {
                if matches!(byte, b'i' | b'm' | b's' | b'R' | b'U' | b'u' | b'x') {
                    has_flag = true;
                } else if byte != b'-' {
                    break;
                }
                cursor += 1;
            }
            if has_flag && matches!(bytes.get(cursor), Some(&b')' | &b':')) {
                return true;
            }
        }
        index += 1;
    }
    false
}

fn has_posix_character_class(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    (0..bytes.len().saturating_sub(2)).any(|start| {
        bytes[start..].starts_with(b"[[:")
            && !is_escaped(bytes, start)
            && bytes[start + 3..].windows(3).any(|window| window == b":]]")
    })
}

fn is_escaped(bytes: &[u8], index: usize) -> bool {
    bytes[..index]
        .iter()
        .rev()
        .take_while(|&&byte| byte == b'\\')
        .count()
        % 2
        == 1
}

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::*;

    static LINTER: LazyLock<Linter> = LazyLock::new(|| {
        let mut linter = Linter::new();
        linter.config = LinterConfig::default_disable_all_lints();
        linter.config.lints.enable_lints = vec![LINT_NAME.into()];
        linter
    });

    #[test]
    fn test_anchors_with_non_regex_operators() {
        expect_lint_message(
            &LINTER,
            r#"http.host eq "^example.com""#,
            expect![[r#"
            Found regex syntax with a non-regex comparison operator (regex_string_literal)
            This string contains regex syntax, but only `matches` interprets regular expressions. Use `matches` or remove the regex syntax."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host eq "example.com$""#,
            expect![[r#"
            Found regex syntax with a non-regex comparison operator (regex_string_literal)
            This string contains regex syntax, but only `matches` interprets regular expressions. Use `matches` or remove the regex syntax."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host wildcard "prefix(?i)example""#,
            expect![[r#"
                Found regex syntax with a non-regex comparison operator (regex_string_literal)
                This string contains regex syntax, but only `matches` interprets regular expressions. Use `matches` or remove the regex syntax."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host strict wildcard "example$""#,
            expect![[r#"
                Found regex syntax with a non-regex comparison operator (regex_string_literal)
                This string contains regex syntax, but only `matches` interprets regular expressions. Use `matches` or remove the regex syntax."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host in {"example.com$" "other"}"#,
            expect![[r#"
                Found regex syntax with a non-regex comparison operator (regex_string_literal)
                This string contains regex syntax, but only `matches` interprets regular expressions. Use `matches` or remove the regex syntax."#]],
        );
    }

    #[test]
    fn test_inline_regex_flags() {
        for flag in ["i", "m", "s", "R", "U", "u", "x"] {
            expect_lint_message(
                &LINTER,
                &format!(r#"http.host eq "prefix(?{flag})suffix""#),
                expect![[r#"
                    Found regex syntax with a non-regex comparison operator (regex_string_literal)
                    This string contains regex syntax, but only `matches` interprets regular expressions. Use `matches` or remove the regex syntax."#]],
            );
        }
    }

    #[test]
    fn test_posix_character_classes() {
        expect_lint_message(
            &LINTER,
            r#"http.host eq "[[:alnum:]]""#,
            expect![[r#"
            Found regex syntax with a non-regex comparison operator (regex_string_literal)
            This string contains regex syntax, but only `matches` interprets regular expressions. Use `matches` or remove the regex syntax."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host eq "prefix[[:word:]]suffix""#,
            expect![[r#"
                Found regex syntax with a non-regex comparison operator (regex_string_literal)
                This string contains regex syntax, but only `matches` interprets regular expressions. Use `matches` or remove the regex syntax."#]],
        );
    }

    #[test]
    fn test_combined_regex_indicators() {
        expect_lint_message(
            &LINTER,
            r#"http.host eq "^(?im)prefix[[:alnum:]]suffix$""#,
            expect![[r#"
                Found regex syntax with a non-regex comparison operator (regex_string_literal)
                This string contains regex syntax, but only `matches` interprets regular expressions. Use `matches` or remove the regex syntax."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host contains "middle[[:word:]](?x)tail""#,
            expect![[r#"
                Found regex syntax with a non-regex comparison operator (regex_string_literal)
                This string contains regex syntax, but only `matches` interprets regular expressions. Use `matches` or remove the regex syntax."#]],
        );
    }

    #[test]
    fn test_matches_and_escaped_anchors_do_not_warn() {
        assert_no_lint_message(&LINTER, r#"http.host matches "^example.com$""#);
        assert_no_lint_message(&LINTER, r#"http.host eq r"\^example.com""#);
        assert_no_lint_message(&LINTER, r#"http.host eq r"example.com\$""#);
        assert_no_lint_message(&LINTER, r#"http.host eq r"\(?i)""#);
        assert_no_lint_message(&LINTER, r#"http.host eq r"\[[:alnum:]]""#);
        assert_no_lint_message(&LINTER, r#"http.host eq "plain.example.com""#);
    }
}
