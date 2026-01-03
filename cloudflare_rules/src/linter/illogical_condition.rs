use super::*;
use crate::ast_printer::AstPrintVisitor;
use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, LogicalExpr, LogicalOp, OrderingOp, UnaryOp, Visitor,
};
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct IllogicalCondition;
impl Lint for IllogicalCondition {
    fn name(&self) -> &'static str {
        "illogical_condition"
    }

    fn category(&self) -> Category {
        Category::Style
    }

    fn lint(&self, _config: &LinterConfig, ast: &FilterAst) -> Vec<LintReport> {
        // Check for illogical conditions
        // A eq 1 and A eq 2 => always false
        // A ne 1 or A ne 2 => always true
        //
        // Special care for different comparisons options
        // A eq 1
        // A in {1 2}
        //
        // A ne 1
        // not A eq 1
        // not A in {1 2}
        //
        // Possible extensions for strings
        // If regex or wildcard matches do not use any placeholders, they could be considered as equal matches

        struct IllogicalConditionsVisitor {
            result: Vec<LintReport>,
        }
        let mut visitor = IllogicalConditionsVisitor { result: Vec::new() };

        impl Visitor<'_> for IllogicalConditionsVisitor {
            fn visit_logical_expr(&mut self, node: &'_ LogicalExpr) {
                // Check for illogical conditions here
                if let LogicalExpr::Combining {
                    op,
                    items,
                    reverse_span,
                } = node
                {
                    match op {
                        LogicalOp::And => {
                            // Collect found index expressions to check for duplicates
                            let mut found_lhs = Vec::new();

                            // Check for always false conditions
                            for e in items {
                                // Analyze each expression
                                if let LogicalExpr::Comparison(ComparisonExpr {
                                    lhs,
                                    op:
                                        ComparisonOpExpr::Ordering {
                                            op: OrderingOp::Equal,
                                            ..
                                        }
                                        | ComparisonOpExpr::OneOf(..),
                                    ..
                                }) = e
                                {
                                    if found_lhs.contains(&lhs) {
                                        // Found duplicate equality comparison on same field
                                        // This is always false
                                        let lhs_str = AstPrintVisitor::value_expr_to_string(lhs);
                                        self.result.push(LintReport {
                                            id: "illogical_condition".into(),
                                            url: None,
                                            title: "Found illogical condition with AND".into(),
                                            message: format!(
                                                "The value `{lhs_str}` is compared for equality \
                                                 multiple times in an AND expression.",
                                            ),
                                            span: Span::ReverseByte(reverse_span.clone()),
                                        });
                                    } else {
                                        found_lhs.push(lhs);
                                    }
                                }
                            }
                        }
                        LogicalOp::Or => {
                            // Collect found index expressions to check for duplicates
                            let mut found_lhs = Vec::new();

                            // Check for always true conditions
                            for e in items {
                                // Analyze each expression
                                match e {
                                    LogicalExpr::Comparison(ComparisonExpr {
                                        lhs,
                                        op:
                                            ComparisonOpExpr::Ordering {
                                                op: OrderingOp::NotEqual,
                                                ..
                                            },
                                        ..
                                    }) => {
                                        if found_lhs.contains(&lhs) {
                                            // Found duplicate equality comparison on same field
                                            // This is always false
                                            let lhs_str =
                                                AstPrintVisitor::value_expr_to_string(lhs);
                                            self.result.push(LintReport {
                                                id: "illogical_condition".into(),
                                                url: None,
                                                title: "Found illogical condition with OR".into(),
                                                message: format!(
                                                    "The value `{lhs_str}` is compared for \
                                                     inequality multiple times in an OR \
                                                     expression.",
                                                ),
                                                span: Span::ReverseByte(reverse_span.clone()),
                                            });
                                        } else {
                                            found_lhs.push(lhs);
                                        }
                                    }
                                    LogicalExpr::Unary {
                                        op: UnaryOp::Not,
                                        arg,
                                        ..
                                    } => {
                                        if let LogicalExpr::Comparison(ComparisonExpr {
                                            lhs,
                                            op:
                                                ComparisonOpExpr::Ordering {
                                                    op: OrderingOp::Equal,
                                                    ..
                                                }
                                                | ComparisonOpExpr::OneOf(..),
                                            ..
                                        }) = &**arg
                                        {
                                            if found_lhs.contains(&lhs) {
                                                // Found duplicate equality comparison on same field
                                                // This is always false
                                                let lhs_str =
                                                    AstPrintVisitor::value_expr_to_string(lhs);
                                                self.result.push(LintReport {
                                                    id: "illogical_condition".into(),
                                                    url: None,
                                                    title: "Found illogical condition with OR"
                                                        .into(),
                                                    message: format!(
                                                        "The value `{lhs_str}` is compared for \
                                                         inequality multiple times in an OR \
                                                         expression.",
                                                    ),
                                                    span: Span::ReverseByte(reverse_span.clone()),
                                                });
                                            } else {
                                                found_lhs.push(lhs);
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }

                self.visit_expr(node);
            }
        }

        ast.walk(&mut visitor);
        visitor.result
    }
}

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::*;

    static LINTER: LazyLock<Linter> = LazyLock::new(|| {
        let mut linter = Linter::new();
        linter.config = LinterConfig::default_disable_all_lints();
        linter.config.lints.enable_lints = vec![IllogicalCondition.name().into()];
        linter
    });

    #[test]
    fn test_illogical_conditions_and() {
        expect_lint_message(
            &LINTER,
            r#"http.host eq "example.com" and http.host eq "example.org""#,
            expect![[r#"
                Found illogical condition with AND (illogical_condition)
                The value `http.host` is compared for equality multiple times in an AND expression."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host eq "example.com" and http.host in { "example.org" }"#,
            expect![[r#"
                Found illogical condition with AND (illogical_condition)
                The value `http.host` is compared for equality multiple times in an AND expression."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host in { "example.com" } and http.host eq "example.org""#,
            expect![[r#"
                Found illogical condition with AND (illogical_condition)
                The value `http.host` is compared for equality multiple times in an AND expression."#]],
        );
    }

    #[test]
    fn test_illogical_conditions_and_parens() {
        expect_lint_message(
            &LINTER,
            r#"http.host eq "example.com" and (http.host eq "example.org")"#,
            expect![[r#"
                Found illogical condition with AND (illogical_condition)
                The value `http.host` is compared for equality multiple times in an AND expression."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"(http.host eq "example.com") and http.host in { "example.org" }"#,
            expect![[r#"
                Found illogical condition with AND (illogical_condition)
                The value `http.host` is compared for equality multiple times in an AND expression."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"(http.host in { "example.com" }) and (http.host eq "example.org")"#,
            expect![[r#"
                Found illogical condition with AND (illogical_condition)
                The value `http.host` is compared for equality multiple times in an AND expression."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host eq "example.com" and (ip.src eq 1.2.3.4 and http.host eq "example.org")"#,
            expect![[r#"
                Found illogical condition with AND (illogical_condition)
                The value `http.host` is compared for equality multiple times in an AND expression."#]],
        );
    }

    #[test]
    fn test_illogical_conditions_or() {
        expect_lint_message(
            &LINTER,
            r#"http.host != "example.com" or http.host != "example.org""#,
            expect![[r#"
                Found illogical condition with OR (illogical_condition)
                The value `http.host` is compared for inequality multiple times in an OR expression."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"not http.host eq "example.com" or http.host != "example.org""#,
            expect![[r#"
                Found illogical condition with OR (illogical_condition)
                The value `http.host` is compared for inequality multiple times in an OR expression."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host != "example.com" or not http.host eq "example.org""#,
            expect![[r#"
                Found illogical condition with OR (illogical_condition)
                The value `http.host` is compared for inequality multiple times in an OR expression."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.host != "example.com" or not http.host in { "example.org" }"#,
            expect![[r#"
                Found illogical condition with OR (illogical_condition)
                The value `http.host` is compared for inequality multiple times in an OR expression."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"not http.host in { "example.com" } or http.host ne "example.org""#,
            expect![[r#"
                Found illogical condition with OR (illogical_condition)
                The value `http.host` is compared for inequality multiple times in an OR expression."#]],
        );
    }
}
