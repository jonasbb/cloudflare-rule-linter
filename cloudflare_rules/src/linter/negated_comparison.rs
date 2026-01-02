use super::*;
use crate::ast_printer::AstPrintVisitor;
use wirefilter::{ComparisonExpr, ComparisonOpExpr, LogicalExpr, OrderingOp, UnaryOp, Visitor};
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct NegatedComparison;

impl Lint for NegatedComparison {
    fn name(&self) -> &'static str {
        "negated_comparison"
    }

    fn category(&self) -> Category {
        Category::Style
    }

    fn lint(&self, _config: &LinterConfig, ast: &FilterAst) -> String {
        struct NegatedComparisonVisitor {
            result: String,
        }

        let mut visitor = NegatedComparisonVisitor {
            result: String::new(),
        };

        impl Visitor<'_> for NegatedComparisonVisitor {
            fn visit_logical_expr(&mut self, node: &'_ LogicalExpr) {
                if let LogicalExpr::Unary {
                    op: UnaryOp::Not,
                    arg,
                } = node
                    && let LogicalExpr::Comparison(comp @ ComparisonExpr { .. }) = &**arg
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

                            self.result += &format!(
                                "Found negated comparison: not {inner}\nConsider simplifying to: \
                                 {suggested_expr}\n",
                            );
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
                Found negated comparison: not http.host eq "example.com"
                Consider simplifying to: http.host ne "example.com"
            "#]],
        );
    }

    #[test]
    fn test_simplify_negated_lt() {
        expect_lint_message(
            &LINTER,
            r#"not http.response.code lt 400"#,
            expect![[r#"
                Found negated comparison: not http.response.code lt 400
                Consider simplifying to: http.response.code ge 400
            "#]],
        );
    }

    #[test]
    fn test_simplify_negated_le() {
        expect_lint_message(
            &LINTER,
            r#"not http.response.code le 200"#,
            expect![[r#"
                Found negated comparison: not http.response.code le 200
                Consider simplifying to: http.response.code gt 200
            "#]],
        );
    }

    #[test]
    fn test_simplify_negated_gt() {
        expect_lint_message(
            &LINTER,
            r#"not ip.src.asnum gt 1024"#,
            expect![[r#"
                Found negated comparison: not ip.src.asnum gt 1024
                Consider simplifying to: ip.src.asnum le 1024
            "#]],
        );
    }

    #[test]
    fn test_simplify_negated_ge() {
        expect_lint_message(
            &LINTER,
            r#"not ip.src.asnum ge 80"#,
            expect![[r#"
                Found negated comparison: not ip.src.asnum ge 80
                Consider simplifying to: ip.src.asnum lt 80
            "#]],
        );
    }
}
