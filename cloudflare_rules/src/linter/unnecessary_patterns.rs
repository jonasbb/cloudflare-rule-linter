use super::*;
use regex_syntax::Parser;
use regex_syntax::hir::{Hir, HirKind, Look};
use wirefilter::{ComparisonExpr, ComparisonOpExpr, Visitor};

static LINT_NAME: &str = "unnecessary_patterns";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Detect regex and wildcard patterns that can be simplified to `eq` or `contains` expressions.",
        category: Category::Style,
        lint_fn: lint,
        lint_value_fn: lint_value,
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = RegexRawStringsVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

fn lint_value(_config: &LinterConfig, ast: &FilterValueAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = RegexRawStringsVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

/// Returns true if the given regex HIR represents a full string literal match (e.g., `^abc$` or `^(?:aa|bb|cc)$`), false otherwise.
///
/// Full string means that the start `^` and end `$` anchors are present, and the content in between is a literal string.
fn is_full_string_literal(hir: &Hir) -> bool {
    // Match simple cases like: ^abc$
    if let HirKind::Concat(items) = hir.kind()
        && items.len() == 3
        && let HirKind::Look(Look::Start) = items[0].kind()
        && let HirKind::Literal(_) = items[1].kind()
        && let HirKind::Look(Look::End) = items[2].kind()
    {
        true
    } else {
        false
    }
}

/// Returns true if the given regex HIR represents a full string literal match (e.g., `^(?:aa|bb|cc)$`), false otherwise.
///
/// Full string means that the start `^` and end `$` anchors are present, and the content in between is an alternation of literal strings.
fn is_full_string_literal_alteration(hir: &Hir) -> bool {
    // Match full strings with inner alterations: ^(?:aa|bb|cc)$
    // Importantly, without a capture group
    if let HirKind::Concat(items) = hir.kind()
        && items.len() == 3
        && let HirKind::Look(Look::Start) = items[0].kind()
        && items[1].properties().is_alternation_literal()
        && let HirKind::Look(Look::End) = items[2].kind()
    {
        true
    }
    // Match full strings with inner alterations: ^(aa|bb|cc)$
    // This accounts for capture groups
    else if let HirKind::Concat(items) = hir.kind()
        && items.len() == 3
        && let HirKind::Look(Look::Start) = items[0].kind()
        && let HirKind::Capture(cap) = items[1].kind()
        && cap.sub.properties().is_alternation_literal()
        && let HirKind::Look(Look::End) = items[2].kind()
    {
        true
    } else {
        false
    }
}

/// Ensure regex matches use raw string literals (r"...") instead of normal quoted strings
#[derive(Default)]
struct RegexRawStringsVisitor {
    result: Vec<LintReport>,
}

impl Visitor<'_> for RegexRawStringsVisitor {
    fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
        if let ComparisonOpExpr::Matches(regex) = &node.op {
            let hir = Parser::new()
                .parse(regex.as_str())
                .unwrap_or_else(|_| Hir::empty());
            if is_full_string_literal(&hir) {
                self.result.push(LintReport {
                    id: LINT_NAME.into(),
                    url: Some(create_url(LINT_NAME)),
                    title: "Found regex match without special characters".into(),
                    message: "The regex match can be simplified to an equality check with `eq \
                              \"...\"`."
                        .to_string(),
                    span: Span::ReverseByte(node.reverse_span.clone()),
                });
            } else if is_full_string_literal_alteration(&hir) {
                self.result.push(LintReport {
                    id: LINT_NAME.into(),
                    url: Some(create_url(LINT_NAME)),
                    title: "Found regex match without special characters".into(),
                    message: "The regex match can be simplified to a list check `in {\"...\" \
                              \"...\"}`"
                        .to_string(),
                    span: Span::ReverseByte(node.reverse_span.clone()),
                });
            } else if hir.properties().is_literal() {
                self.result.push(LintReport {
                    id: LINT_NAME.into(),
                    url: Some(create_url(LINT_NAME)),
                    title: "Found regex match without special characters".into(),
                    message: "The regex match can be simplified to a `contains \"...\"`"
                        .to_string(),
                    span: Span::ReverseByte(node.reverse_span.clone()),
                });
            }
        }
        if let ComparisonOpExpr::StrictWildcard(wildcard) = &node.op
            && !(**wildcard.pattern()).contains(&b'*')
        {
            self.result.push(LintReport {
                id: LINT_NAME.into(),
                url: Some(create_url(LINT_NAME)),
                title: "Found wildcard match without any wildcards `*`".into(),
                message: "The strict wildcard can be simplified to an equality check with `eq \
                          \"...\"`."
                    .to_string(),
                span: Span::ReverseByte(node.reverse_span.clone()),
            });
        }

        self.visit_expr(node);
    }
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
    fn test_wildcard_no_wildcards() {
        assert_no_lint_message(&LINTER, r#"http.host wildcard "example""#);
    }

    #[test]
    fn test_strict_wildcard_no_wildcards() {
        expect_lint_message(
            &LINTER,
            r#"http.host strict wildcard "example""#,
            expect![[r#"
                Found wildcard match without any wildcards `*` (unnecessary_patterns)
                The strict wildcard can be simplified to an equality check with `eq "..."`."#]],
        );
    }

    #[test]
    fn test_strict_wildcard_with_wildcards() {
        assert_no_lint_message(&LINTER, r#"http.host strict wildcard "example*""#);
    }

    #[test]
    fn test_regex_literal_contains() {
        expect_lint_message(
            &LINTER,
            r#"http.host matches "example""#,
            expect![[r#"
                Found regex match without special characters (unnecessary_patterns)
                The regex match can be simplified to a `contains "..."`"#]],
        );
    }

    #[test]
    fn test_regex_with_escaping_contains() {
        assert_no_lint_message(&LINTER, r#"http.host matches "example\...""#);
    }

    #[test]
    fn test_regex_literal_full_string() {
        // Simple full string literal
        expect_lint_message(
            &LINTER,
            r#"http.host matches "^example$""#,
            expect![[r#"
                Found regex match without special characters (unnecessary_patterns)
                The regex match can be simplified to an equality check with `eq "..."`."#]],
        );
        // Literal alteration without capture group
        expect_lint_message(
            &LINTER,
            r#"http.host matches "^(?:ex|am|ple)$""#,
            expect![[r#"
                Found regex match without special characters (unnecessary_patterns)
                The regex match can be simplified to a list check `in {"..." "..."}`"#]],
        );
        // Literal alteration with capture group
        expect_lint_message(
            &LINTER,
            r#"http.host matches "^(ex|am|ple)$""#,
            expect![[r#"
                Found regex match without special characters (unnecessary_patterns)
                The regex match can be simplified to a list check `in {"..." "..."}`"#]],
        );
    }

    #[test]
    fn test_regex_with_escaping_full_string() {
        assert_no_lint_message(&LINTER, r#"http.host matches "^example\...$""#);
    }
}
