use super::*;
use crate::ast_printer::AstPrintVisitor;
use wirefilter::{ComparisonOpExpr, LogicalExpr, OrderingOp, UnaryOp, Visitor};
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct NegatedComparison;

impl Lint for NegatedComparison {
    fn name(&self) -> &'static str {
        "negated_comparison"
    }

    fn category(&self) -> Category {
        Category::Style
    }

    fn lint(&self, _config: &LinterConfig, ast: &FilterAst) -> Vec<LintReport> {
        struct NegatedComparisonVisitor {
            result: Vec<LintReport>,
        }

        let mut visitor = NegatedComparisonVisitor { result: Vec::new() };

        impl Visitor<'_> for NegatedComparisonVisitor {
            fn visit_logical_expr(&mut self, node: &'_ LogicalExpr) {
                if let LogicalExpr::Unary {
                    op: UnaryOp::Not,
                    arg,
                    reverse_span,
                } = node
                    && let LogicalExpr::Comparison(comp) = &**arg
                {
                    // Only handle ordering comparisons (eq, ne, lt, le, gt, ge)
                    if let ComparisonOpExpr::Ordering { op, .. } = &comp.op {
                        use OrderingOp;
                        let suggestion_op = match op {
                            OrderingOp::Equal => Some(OrderingOp::NotEqual),
                            OrderingOp::NotEqual => Some(OrderingOp::Equal),
                            OrderingOp::LessThan => Some(OrderingOp::GreaterThanEqual),
                            OrderingOp::LessThanEqual => Some(OrderingOp::GreaterThan),
                            OrderingOp::GreaterThan => Some(OrderingOp::LessThanEqual),
                            OrderingOp::GreaterThanEqual => Some(OrderingOp::LessThan),
                        };

                        if let Some(sugg) = suggestion_op {
                            let inner = AstPrintVisitor::comparison_expr_to_string(comp);
                            // Reconstruct a ComparisonExpr string with the suggested op
                            // We reuse the AST printer on the original and then replace the operator
                            let sugg_str = match sugg {
                                OrderingOp::Equal => " eq ",
                                OrderingOp::NotEqual => " ne ",
                                OrderingOp::GreaterThanEqual => " ge ",
                                OrderingOp::LessThanEqual => " le ",
                                OrderingOp::GreaterThan => " gt ",
                                OrderingOp::LessThan => " lt ",
                            };

                            // Split on known operator tokens to replace
                            // TODO: add replacements for c style operators
                            let suggested_expr = inner
                                .replace(" eq ", sugg_str)
                                .replace(" == ", sugg_str)
                                .replace(" ne ", sugg_str)
                                .replace(" != ", sugg_str)
                                .replace(" gt ", sugg_str)
                                .replace(" > ", sugg_str)
                                .replace(" lt ", sugg_str)
                                .replace(" < ", sugg_str)
                                .replace(" ge ", sugg_str)
                                .replace(" >= ", sugg_str)
                                .replace(" le ", sugg_str)
                                .replace(" <= ", sugg_str);

                            self.result.push(LintReport {
                                id: "negated_comparison".into(),
                                url: None,
                                title: "Found negated comparison".into(),
                                message: format!(
                                    "Consider simplifying from `not {inner}` to `{suggested_expr}`",
                                ),
                                span: Span::ReverseByte(reverse_span.clone()),
                            });
                        }
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
        linter.config.lints.enable_lints = vec![NegatedComparison.name().into()];
        linter
    });

    #[test]
    fn test_simplify_negated_eq() {
        expect_lint_message(
            &LINTER,
            r#"not http.host eq "example.com""#,
            expect![[r#"
                Found negated comparison (negated_comparison)
                Consider simplifying from `not http.host eq "example.com"` to `http.host ne "example.com"`"#]],
        );
    }

    #[test]
    fn test_simplify_negated_lt() {
        expect_lint_message(
            &LINTER,
            r#"not http.response.code lt 400"#,
            expect![[r#"
                Found negated comparison (negated_comparison)
                Consider simplifying from `not http.response.code lt 400` to `http.response.code ge 400`"#]],
        );
    }

    #[test]
    fn test_simplify_negated_le() {
        expect_lint_message(
            &LINTER,
            r#"not http.response.code le 200"#,
            expect![[r#"
                Found negated comparison (negated_comparison)
                Consider simplifying from `not http.response.code le 200` to `http.response.code gt 200`"#]],
        );
    }

    #[test]
    fn test_simplify_negated_gt() {
        expect_lint_message(
            &LINTER,
            r#"not ip.src.asnum gt 1024"#,
            expect![[r#"
                Found negated comparison (negated_comparison)
                Consider simplifying from `not ip.src.asnum gt 1024` to `ip.src.asnum le 1024`"#]],
        );
    }

    #[test]
    fn test_simplify_negated_ge() {
        expect_lint_message(
            &LINTER,
            r#"not ip.src.asnum ge 80"#,
            expect![[r#"
                Found negated comparison (negated_comparison)
                Consider simplifying from `not ip.src.asnum ge 80` to `ip.src.asnum lt 80`"#]],
        );
    }

    #[test]
    fn test_simplify_negated_eq_parns() {
        expect_lint_message(
            &LINTER,
            r#"not ( http.host eq "example.com" )"#,
            expect![[r#"
                Found negated comparison (negated_comparison)
                Consider simplifying from `not http.host eq "example.com"` to `http.host ne "example.com"`"#]],
        );
    }
}
