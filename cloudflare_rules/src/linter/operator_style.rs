use super::*;
use crate::config::OperatorStyleMode;
use wirefilter::{ComparisonOpExpr, LogicalExpr, Visitor};

static LINT_NAME: &str = "operator_style";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Enforce a consistent operator notation (english vs C-like).",
        category: Category::Style,
        lint_fn: lint
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum OpStyle {
    English,
    CLike,
}

fn lint(config: &LinterConfig, ast: &FilterAst, expr: &str) -> Vec<LintReport> {
    struct V<'a> {
        result: Vec<LintReport>,
        first: Option<OpStyle>,
        mode: OperatorStyleMode,
        expr: &'a str,
    }
    impl<'a> V<'a> {
        fn check_style_for_next_operator(
            &mut self,
            mut remaining: &str,
            reverse_span_start: usize,
        ) {
            let original_remaining = remaining;
            let original_length = remaining.len();

            // These characters are not semantically meaningful here.
            // This includes the original space characters
            // plus ( and ) which are used for parenthesized expressions but we treat them transparently
            const SKIPPABLE_CHARS: &[char] = &[' ', '\r', '\n', '(', ')'];
            const ENGLISH_OPERATORS: &[&str] = &[
                "eq",
                "ne",
                "ge",
                "le",
                "gt",
                "lt",
                "matches",
                "bitwise_and",
                "and",
                "or",
                "xor",
                "not",
            ];
            const CLIKE_OPERATORS: &[&str] = &[
                "==", "!=", ">=", "<=", ">", "<", "~", "&", "&&", "||", "^^", "!",
            ];
            debug_assert_eq!(ENGLISH_OPERATORS.len(), CLIKE_OPERATORS.len());

            remaining = remaining.trim_start_matches(SKIPPABLE_CHARS);
            let skipped_chars = original_length - remaining.len();

            match (self.mode, self.first) {
                (OperatorStyleMode::EnforceEnglish, _)
                | (OperatorStyleMode::ProhibitMixed, Some(OpStyle::English)) => {
                    for (i, cop) in CLIKE_OPERATORS.iter().enumerate() {
                        if remaining.starts_with(cop) {
                            // Handle C-style operators

                            let (title, message) = if self.mode == OperatorStyleMode::EnforceEnglish
                            {
                                (
                                    "Prefer english operator notation",
                                    format!(
                                        "Prefer english operator notation; rewrite `{}` to `{}`",
                                        cop, ENGLISH_OPERATORS[i]
                                    ),
                                )
                            } else {
                                (
                                    "Mixed operator styles",
                                    format!(
                                        "Found mixed operator styles; rewrite `{}` to `{}`",
                                        cop, ENGLISH_OPERATORS[i]
                                    ),
                                )
                            };

                            self.result.push(LintReport {
                                id: LINT_NAME.into(),
                                url: Some(create_url(LINT_NAME)),
                                title: title.into(),
                                message,
                                // From the original span,
                                // account for the skipped characters and the operator length to get the correct span for the operator itself
                                span: Span::ReverseByte(
                                    reverse_span_start.saturating_sub(skipped_chars)
                                        ..(reverse_span_start
                                            .saturating_sub(skipped_chars)
                                            .saturating_sub(cop.len())),
                                ),
                            });
                        }
                    }
                }
                (OperatorStyleMode::EnforceCLike, _)
                | (OperatorStyleMode::ProhibitMixed, Some(OpStyle::CLike)) => {
                    for (i, eop) in ENGLISH_OPERATORS.iter().enumerate() {
                        if remaining.starts_with(eop) {
                            // Handle english operators

                            let (title, message) = if self.mode == OperatorStyleMode::EnforceCLike {
                                (
                                    "Prefer C-like operator notation",
                                    format!(
                                        "Prefer C-like operator notation; rewrite `{}` to `{}`",
                                        eop, CLIKE_OPERATORS[i]
                                    ),
                                )
                            } else {
                                (
                                    "Mixed operator styles",
                                    format!(
                                        "Found mixed operator styles; rewrite `{}` to `{}`",
                                        eop, CLIKE_OPERATORS[i]
                                    ),
                                )
                            };

                            self.result.push(LintReport {
                                id: LINT_NAME.into(),
                                url: Some(create_url(LINT_NAME)),
                                title: title.into(),
                                message,
                                // From the original span,
                                // account for the skipped characters and the operator length to get the correct span for the operator itself
                                span: Span::ReverseByte(
                                    reverse_span_start.saturating_sub(skipped_chars)
                                        ..(reverse_span_start
                                            .saturating_sub(skipped_chars)
                                            .saturating_sub(eop.len())),
                                ),
                            });
                        }
                    }
                }

                (OperatorStyleMode::ProhibitMixed, None) => {
                    // Check what kind of operators we see, then call itself recursively for the reporting
                    for eop in ENGLISH_OPERATORS {
                        if remaining.starts_with(eop) {
                            self.first = Some(OpStyle::English);
                            break;
                        }
                    }

                    for cop in CLIKE_OPERATORS {
                        if remaining.starts_with(cop) {
                            self.first = Some(OpStyle::CLike);
                            break;
                        }
                    }

                    // Now that we have a style, recurse into detection
                    assert!(
                        self.first.is_some(),
                        "If we are in ProhibitMixed mode, we should have detected an operator \
                         style by now"
                    );
                    self.check_style_for_next_operator(original_remaining, reverse_span_start);
                }
            }
        }
    }

    impl<'a> Visitor<'a> for V<'a> {
        fn visit_logical_expr(&mut self, node: &'a LogicalExpr) {
            self.visit_expr(node);

            let expr = self.expr;

            match node {
                LogicalExpr::Combining { items, .. } => {
                    // For each logical expression, check what is the operator used behind it
                    // Skip the last element as there is something unrelated or nothing behind it.
                    for item in &items[..items.len().saturating_sub(1)] {
                        let start = expr.len().saturating_sub(item.get_reverse_span().end);
                        if start <= expr.len() {
                            self.check_style_for_next_operator(
                                &expr[start..],
                                item.get_reverse_span().end,
                            );
                        }
                    }
                }
                LogicalExpr::Comparison(comparison_expr) => {
                    match &comparison_expr.op {
                        ComparisonOpExpr::Ordering { .. }
                        | ComparisonOpExpr::Int { .. }
                        | ComparisonOpExpr::Matches(..) => {
                            // Skip the LHS expression and look at the next value afterwards.
                            let start = expr
                                .len()
                                .saturating_sub(comparison_expr.lhs_expr().reverse_span.end);
                            if start <= expr.len() {
                                self.check_style_for_next_operator(
                                    &expr[start..],
                                    comparison_expr.lhs_expr().reverse_span.end,
                                );
                            }
                        }

                        // These only have english operators, so ignore them for style detection
                        ComparisonOpExpr::Contains(_)
                        | ComparisonOpExpr::Wildcard(_)
                        | ComparisonOpExpr::StrictWildcard(_)
                        | ComparisonOpExpr::OneOf(_)
                        | ComparisonOpExpr::InList { .. }
                        | ComparisonOpExpr::ContainsOneOf(_) => {}

                        // This has no operator to look at
                        ComparisonOpExpr::IsTrue => {}
                    }
                }
                LogicalExpr::Parenthesized(_) => {
                    // This has no operator to look at
                }
                LogicalExpr::Unary { .. } => {
                    let start = expr.len().saturating_sub(node.get_reverse_span().start);
                    self.check_style_for_next_operator(
                        &expr[start..],
                        node.get_reverse_span().start,
                    );
                }
            }
        }
    }

    let mut visitor = V {
        result: Vec::new(),
        first: None,
        mode: config.settings.operator_style_mode,
        expr,
    };

    ast.walk(&mut visitor);
    visitor.result
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
    fn test_prohibit_mixed_accepts_same_style() {
        assert_no_lint_message(
            &LINTER,
            r#"http.host eq "example.com" and http.host eq "example.org""#,
        );
    }

    #[test]
    fn test_prohibit_mixed_detects_mixed() {
        expect_lint_message(
            &LINTER,
            r#"http.host == "example.com" and http.host eq "example.org""#,
            expect![[r#"
                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `eq` to `==`

                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `and` to `&&`"#]],
        );
    }

    #[test]
    fn test_enforce_english_rejects_clike() {
        let mut l = Linter::new();
        l.config = LinterConfig::default_disable_all_lints();
        l.config.lints.enable_lints = vec![LINT_NAME.into()];
        l.config.settings.operator_style_mode = OperatorStyleMode::EnforceEnglish;

        expect_lint_message(
            &l,
            r#"http.host == "example.com""#,
            expect![[r#"
                Prefer english operator notation (operator_style)
                Prefer english operator notation; rewrite `==` to `eq`"#]],
        );
    }

    #[test]
    fn test_enforce_clike_rejects_english() {
        let mut l = Linter::new();
        l.config = LinterConfig::default_disable_all_lints();
        l.config.lints.enable_lints = vec![LINT_NAME.into()];
        l.config.settings.operator_style_mode = OperatorStyleMode::EnforceCLike;

        expect_lint_message(
            &l,
            r#"http.host eq "example.com""#,
            expect![[r#"
                Prefer C-like operator notation (operator_style)
                Prefer C-like operator notation; rewrite `eq` to `==`"#]],
        );
    }

    #[test]
    fn test_prohibit_mixed_ignores_in_and_wildcard() {
        // 'in' and 'wildcard' are english-only and should be ignored for mixing checks
        assert_no_lint_message(&LINTER, r#"http.host == "a" && http.host in { "b" }"#);
        assert_no_lint_message(
            &LINTER,
            r#"http.host eq "a" and http.host wildcard "example*""#,
        );
    }

    #[test]
    fn test_prohibit_mixed_detects_mixed_matches_and_bitwise() {
        // mixing ~ and matches should be flagged
        expect_lint_message(
            &LINTER,
            r#"http.host ~ "a" and http.host matches "b""#,
            expect![[r#"
                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `matches` to `~`

                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `and` to `&&`"#]],
        );

        // mixing & and bitwise_and should be flagged
        expect_lint_message(
            &LINTER,
            r#"ip.src.asnum & 1 and ip.src.asnum bitwise_and 2"#,
            expect![[r#"
                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `bitwise_and` to `&`

                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `and` to `&&`"#]],
        );
    }

    #[test]
    fn test_enforce_english_accepts_english_and_ignores_in() {
        let mut l = Linter::new();
        l.config = LinterConfig::default_disable_all_lints();
        l.config.lints.enable_lints = vec![LINT_NAME.into()];
        l.config.settings.operator_style_mode = OperatorStyleMode::EnforceEnglish;

        // English operators are accepted
        assert_no_lint_message(&l, r#"http.host eq "a" and http.host matches "b""#);
        // 'in' is english-only and should not trigger
        assert_no_lint_message(&l, r#"http.host in { "x" } and http.host eq "y""#);

        // C-like operators should be flagged
        expect_lint_message(
            &l,
            r#"ip.src.asnum & 1"#,
            expect![[r#"
                Prefer english operator notation (operator_style)
                Prefer english operator notation; rewrite `&` to `bitwise_and`"#]],
        );
        // Space around operators is not required, so also test a case without spaces
        expect_lint_message(
            &l,
            r#"ip.src.asnum&2"#,
            expect![[r#"
                Prefer english operator notation (operator_style)
                Prefer english operator notation; rewrite `&` to `bitwise_and`"#]],
        );
    }

    #[test]
    fn test_enforce_clike_accepts_clike_and_ignores_wildcard() {
        let mut l = Linter::new();
        l.config = LinterConfig::default_disable_all_lints();
        l.config.lints.enable_lints = vec![LINT_NAME.into()];
        l.config.settings.operator_style_mode = OperatorStyleMode::EnforceCLike;

        // C-like operators are accepted
        assert_no_lint_message(&l, r#"http.host == "a" && http.host ~ "b""#);
        // wildcard is english-only and should not trigger
        assert_no_lint_message(&l, r#"http.host == "a" && http.host wildcard "b*""#);

        // English operators should be flagged
        expect_lint_message(
            &l,
            r#"ip.src.asnum bitwise_and 1"#,
            expect![[r#"
                Prefer C-like operator notation (operator_style)
                Prefer C-like operator notation; rewrite `bitwise_and` to `&`"#]],
        );
    }

    #[test]
    fn test_prohibit_mixed_logical_and_comparison_and_clike_first() {
        expect_lint_message(
            &LINTER,
            r#"http.host == "a" && http.host eq "b""#,
            expect![[r#"
                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `eq` to `==`"#]],
        );
    }

    #[test]
    fn test_prohibit_mixed_logical_or_ne_english_first() {
        expect_lint_message(
            &LINTER,
            r#"http.host ne "a" || http.host != "b""#,
            expect![[r#"
                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `!=` to `ne`

                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `!` to `not`

                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `||` to `or`"#]],
        );
    }

    #[test]
    fn test_prohibit_mixed_logical_xor_ge_clike_first() {
        expect_lint_message(
            &LINTER,
            r#"ip.src.asnum >= 10 xor ip.src.asnum ge 20"#,
            expect![[r#"
                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `ge` to `>=`

                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `xor` to `^^`"#]],
        );
    }

    #[test]
    fn test_prohibit_mixed_logical_and_eq_english_first() {
        expect_lint_message(
            &LINTER,
            r#"http.host eq "a" && http.host == "b""#,
            expect![[r#"
                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `==` to `eq`

                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `&` to `bitwise_and`

                Mixed operator styles (operator_style)
                Found mixed operator styles; rewrite `&&` to `and`"#]],
        );
    }

    #[test]
    fn test_enforce_clike_string_literals() {
        let mut l = Linter::new();
        l.config = LinterConfig::default_disable_all_lints();
        l.config.lints.enable_lints = vec![LINT_NAME.into()];
        l.config.settings.operator_style_mode = OperatorStyleMode::EnforceCLike;

        // C-like operators are accepted
        assert_no_lint_message(&l, r##"len(concat(r#"http.host eq "abc""#, "")) > 0"##);
    }

    #[test]
    fn test_enforce_clike_string_complicated() {
        let mut l = Linter::new();
        l.config = LinterConfig::default_disable_all_lints();
        l.config.lints.enable_lints = vec![LINT_NAME.into()];
        l.config.settings.operator_style_mode = OperatorStyleMode::EnforceCLike;

        // C-like operators are accepted
        // The "eq" is part of a string literal and should not be flagged
        assert_no_lint_message(
            &l,
            r##" ( len(concat(r#"http.host eq "abc""#, "")) > 0 && http.host == "def" ) && ! http.host != "ghi" "##,
        );
    }
}
