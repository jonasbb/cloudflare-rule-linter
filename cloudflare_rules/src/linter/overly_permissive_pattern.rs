use super::*;
use wirefilter::{ComparisonExpr, ComparisonOpExpr, IdentifierExpr, Visitor};

static LINT_NAME: &str = "overly_permissive_pattern";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Check for regex and wildcard patterns that are overly permissive.",
        category: Category::Correctness,
        lint_fn: lint
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst) -> Vec<LintReport> {
    struct EmptyListVisitor {
        result: Vec<LintReport>,
    }

    let mut visitor = EmptyListVisitor { result: Vec::new() };

    impl Visitor<'_> for EmptyListVisitor {
        fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
            match &node.op {
                ComparisonOpExpr::Matches(pattern) => {
                    #[rustfmt::skip]
                    let mut permissive_patterns = vec![
                        // Matches any character
                        ".",
                        // Matches any string of length 0 or more
                        "", ".*", "^.*", ".*$", "^.*$",
                        // Matches any string of length 1 or more
                        ".+", "^.+", ".+$", "^.+$",
                        // Matches empty string at start or end
                        "^", "$", "|",
                    ];
                    if let IdentifierExpr::Field(field) = &node.lhs.identifier
                        && node.lhs.indexes.is_empty()
                        && (field.name() == "http.request.uri.path"
                            || field.name() == "raw.http.request.uri.path")
                    {
                        // Paths always start with a "/" so these patterns are also overly permissive in that context
                        #[rustfmt::skip]
                        permissive_patterns.extend_from_slice(&[
                            // Matches any string of length 0 or more
                            "/.*", "^/.*", "/.*$", "^/.*$",
                            // Every path has a "/" at the start, so these match any path
                            "/", "^/",
                        ]);
                    }

                    if permissive_patterns.contains(&pattern.as_str()) {
                        self.result.push(LintReport {
                            id: LINT_NAME.into(),
                            url: Some(create_url(LINT_NAME)),
                            title: "Overly permissive pattern".to_string(),
                            message: "Consider using a more specific pattern to avoid unintended \
                                      matches."
                                .to_string(),
                            span: Span::ReverseByte(node.reverse_span.clone()),
                        });
                    }
                }
                ComparisonOpExpr::Wildcard(pattern) => {
                    let mut permissive_patterns: Vec<&[u8]> = vec![b"*"];
                    if let IdentifierExpr::Field(field) = &node.lhs.identifier
                        && node.lhs.indexes.is_empty()
                        && (field.name() == "http.request.uri.path"
                            || field.name() == "raw.http.request.uri.path")
                    {
                        permissive_patterns.push(b"/*");
                    }
                    if permissive_patterns.contains(&&**pattern.pattern()) {
                        self.result.push(LintReport {
                            id: LINT_NAME.into(),
                            url: Some(create_url(LINT_NAME)),
                            title: "Overly permissive pattern".to_string(),
                            message: "Consider using a more specific pattern to avoid unintended \
                                      matches."
                                .to_string(),
                            span: Span::ReverseByte(node.reverse_span.clone()),
                        });
                    }
                }
                ComparisonOpExpr::StrictWildcard(pattern) => {
                    let mut permissive_patterns: Vec<&[u8]> = vec![b"*"];
                    if let IdentifierExpr::Field(field) = &node.lhs.identifier
                        && node.lhs.indexes.is_empty()
                        && (field.name() == "http.request.uri.path"
                            || field.name() == "raw.http.request.uri.query")
                    {
                        permissive_patterns.push(b"/*");
                    }
                    if permissive_patterns.contains(&&**pattern.pattern()) {
                        self.result.push(LintReport {
                            id: LINT_NAME.into(),
                            url: Some(create_url(LINT_NAME)),
                            title: "Overly permissive pattern".to_string(),
                            message: "Consider using a more specific pattern to avoid unintended \
                                      matches."
                                .to_string(),
                            span: Span::ReverseByte(node.reverse_span.clone()),
                        });
                    }
                }
                _ => {}
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
    fn test_broad_regex() {
        expect_lint_message(
            &LINTER,
            r#"http.host matches ".*""#,
            expect![[r#"
                Overly permissive pattern (overly_permissive_pattern)
                Consider using a more specific pattern to avoid unintended matches."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host matches "|""#,
            expect![[r#"
                Overly permissive pattern (overly_permissive_pattern)
                Consider using a more specific pattern to avoid unintended matches."#]],
        );

        assert_no_lint_message(&LINTER, r#"http.host matches "m*""#);
    }

    #[test]
    fn test_broad_wildcard() {
        expect_lint_message(
            &LINTER,
            r#"http.host wildcard "*""#,
            expect![[r#"
                Overly permissive pattern (overly_permissive_pattern)
                Consider using a more specific pattern to avoid unintended matches."#]],
        );

        assert_no_lint_message(&LINTER, r#"http.host wildcard ".*""#);
    }

    #[test]
    fn test_broad_strict_wildcard() {
        expect_lint_message(
            &LINTER,
            r#"http.host strict wildcard "*""#,
            expect![[r#"
                Overly permissive pattern (overly_permissive_pattern)
                Consider using a more specific pattern to avoid unintended matches."#]],
        );

        assert_no_lint_message(&LINTER, r#"http.host strict wildcard ".*""#);
    }

    #[test]
    fn test_broad_path() {
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path matches "/.*""#,
            expect![[r#"
                Overly permissive pattern (overly_permissive_pattern)
                Consider using a more specific pattern to avoid unintended matches."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path wildcard "/*""#,
            expect![[r#"
                Overly permissive pattern (overly_permissive_pattern)
                Consider using a more specific pattern to avoid unintended matches."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path strict wildcard "/*""#,
            expect![[r#"
                Overly permissive pattern (overly_permissive_pattern)
                Consider using a more specific pattern to avoid unintended matches."#]],
        );

        assert_no_lint_message(&LINTER, r#"http.host matches "/.*""#);
        assert_no_lint_message(&LINTER, r#"http.host wildcard "/*""#);
        assert_no_lint_message(&LINTER, r#"http.host strict wildcard "/*""#);
    }
}
