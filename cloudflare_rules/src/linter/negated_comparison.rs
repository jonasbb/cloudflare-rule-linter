use super::*;
use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, FunctionCallArgExpr, IdentifierExpr, IndexExpr, LogicalExpr,
    OrderingOp, UnaryOp, Visitor,
};

static LINT_NAME: &str = "negated_comparison";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Detect comparisons that are negated and suggest using the opposite comparison operator instead.",
        category: Category::Style,
        lint_fn: lint,
        lint_value_fn: lint_value,
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst, expr: &str) -> Vec<LintReport> {
    let mut visitor = NegatedComparisonVisitor::new(expr);
    ast.walk(&mut visitor);
    visitor.result
}

fn lint_value(_config: &LinterConfig, ast: &FilterValueAst, expr: &str) -> Vec<LintReport> {
    let mut visitor = NegatedComparisonVisitor::new(expr);
    ast.walk(&mut visitor);
    visitor.result
}

#[derive(Default)]
struct NegatedComparisonVisitor<'a> {
    result: Vec<LintReport>,
    expr: &'a str,
}

impl<'a> NegatedComparisonVisitor<'a> {
    fn new(expr: &'a str) -> Self {
        Self {
            result: Vec::new(),
            expr,
        }
    }

    fn handle_comparison_suggestion(
        &self,
        comp: &ComparisonExpr,
        op: &OrderingOp,
    ) -> (&'a str, String) {
        let start = self.expr.len().saturating_sub(comp.reverse_span.start);
        let end = self.expr.len().saturating_sub(comp.reverse_span.end);

        // Reconstruct a ComparisonExpr string with the suggested op
        let inner = &self.expr[start..end];

        // Only handle ordering comparisons (eq, ne, lt, le, gt, ge)
        let sugg_str = match op {
            OrderingOp::Equal => " ne ",
            OrderingOp::NotEqual => " eq ",
            OrderingOp::LessThan => " ge ",
            OrderingOp::LessThanEqual => " gt ",
            OrderingOp::GreaterThan => " le ",
            OrderingOp::GreaterThanEqual => " lt ",
        };

        // Split on known operator tokens to replace
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

        (inner, suggested_expr)
    }
}

impl<'a> Visitor<'_> for NegatedComparisonVisitor<'a> {
    fn visit_logical_expr(&mut self, node: &'_ LogicalExpr) {
        if let LogicalExpr::Unary {
            op: UnaryOp::Not,
            arg,
            reverse_span,
        } = node
            && let LogicalExpr::Comparison(comp) = &**arg
            && let ComparisonOpExpr::Ordering { op, .. } = &comp.op
        {
            let (old_expr, suggested_expr) = self.handle_comparison_suggestion(comp, op);

            self.result.push(LintReport {
                id: LINT_NAME.into(),
                url: Some(create_url(LINT_NAME)),
                title: "Found negated comparison".into(),
                message: format!(
                    "Consider simplifying from `not {old_expr}` to `{suggested_expr}`",
                ),
                span: Span::ReverseByte(reverse_span.clone()),
            });
        } else if let LogicalExpr::Unary {
            op: UnaryOp::Not,
            arg,
            reverse_span: _,
        } = node
            && let LogicalExpr::Comparison(ComparisonExpr {
                lhs,
                op: ComparisonOpExpr::IsTrue,
                reverse_span,
            }) = &**arg
            && let IndexExpr {
                identifier: IdentifierExpr::FunctionCallExpr(call_expr),
                indexes,
                reverse_span: _,
            } = lhs
            && indexes.is_empty()
            && let fname = call_expr.function().name()
            && (fname == "all" || fname == "any")
            && let [FunctionCallArgExpr::Logical(expr)] = call_expr.args()
            && let LogicalExpr::Comparison(comp) = &expr
            && let ComparisonOpExpr::Ordering { op, .. } = &comp.op
        {
            let sugg_fn = if fname == "all" { "any" } else { "all" };
            let (old_expr, suggested_expr) = self.handle_comparison_suggestion(comp, op);

            self.result.push(LintReport {
                id: LINT_NAME.into(),
                url: Some(create_url(LINT_NAME)),
                title: "Found negated comparison".into(),
                message: format!(
                    "Consider simplifying from `not {fname}({old_expr})` to \
                     `{sugg_fn}({suggested_expr})`",
                ),
                span: Span::ReverseByte(reverse_span.clone()),
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

    #[test]
    fn test_simplify_negated_any() {
        expect_lint_message(
            &LINTER,
            r#"not any(http.request.headers.names[*] eq "abc")"#,
            expect![[r#"
                Found negated comparison (negated_comparison)
                Consider simplifying from `not any(http.request.headers.names[*] eq "abc")` to `all(http.request.headers.names[*] ne "abc")`"#]],
        );
        expect_lint_message(
            &LINTER,
            r#"not all(http.request.headers.names[*] <= "abc")"#,
            expect![[r#"
                Found negated comparison (negated_comparison)
                Consider simplifying from `not all(http.request.headers.names[*] <= "abc")` to `any(http.request.headers.names[*] gt "abc")`"#]],
        );
    }
}
