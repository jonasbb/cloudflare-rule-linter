use super::*;
use wirefilter::{ComparisonExpr, ComparisonOpExpr, Visitor};

static LINT_NAME: &str = "lower_wildcard";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Detect unnecessary `lower()` calls before case-insensitive wildcard comparisons.",
        category: Category::Style,
        lint_fn: lint,
        lint_value_fn: lint_value,
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = LowerWildcardVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

fn lint_value(_config: &LinterConfig, ast: &FilterValueAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = LowerWildcardVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

#[derive(Default)]
struct LowerWildcardVisitor {
    result: Vec<LintReport>,
}

impl Visitor<'_> for LowerWildcardVisitor {
    fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
        if matches!(&node.op, ComparisonOpExpr::Wildcard(_))
            && let wirefilter::IdentifierExpr::FunctionCallExpr(call) = &node.lhs.identifier
            && node.lhs.indexes.is_empty()
            && call.function().name() == "lower"
        {
            self.result.push(LintReport {
                id: LINT_NAME.into(),
                url: Some(create_url(LINT_NAME)),
                title: "Unnecessary lower() before wildcard comparison".into(),
                message: "Wildcard matching is case-insensitive, so `lower()` can be removed."
                    .into(),
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
    fn test_lower_wildcard() {
        expect_lint_message(
            &LINTER,
            r#"lower(http.request.uri.path) wildcard "/foo/bar/*""#,
            expect![[r#"
                Unnecessary lower() before wildcard comparison (lower_wildcard)
                Wildcard matching is case-insensitive, so `lower()` can be removed."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"lower(http.request.uri.path) wildcard "/Foo/BAR/*""#,
            expect![[r#"
                Unnecessary lower() before wildcard comparison (lower_wildcard)
                Wildcard matching is case-insensitive, so `lower()` can be removed."#]],
        );
    }

    #[test]
    fn test_similar_expressions_do_not_lint() {
        assert_no_lint_message(&LINTER, r#"lower(http.request.uri.path) eq "/foo/bar""#);
        assert_no_lint_message(
            &LINTER,
            r#"lower(http.request.uri.path) strict wildcard "/foo/*""#,
        );
        assert_no_lint_message(&LINTER, r#"upper(http.request.uri.path) wildcard "/foo/*""#);
        assert_no_lint_message(&LINTER, r#"http.request.uri.path wildcard "/foo/*""#);
    }
}
