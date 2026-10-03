use super::*;
use wirefilter::{FunctionCallArgExpr, RhsValue, Visitor};

static LINT_NAME: &str = "substring_index_order";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Detect `substring()` calls with non-negative end indices below their start indices.",
        category: Category::Correctness,
        lint_fn: lint,
        lint_value_fn: lint_value,
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = SubstringIndexOrderVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

fn lint_value(_config: &LinterConfig, ast: &FilterValueAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = SubstringIndexOrderVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

#[derive(Default)]
struct SubstringIndexOrderVisitor {
    result: Vec<LintReport>,
}

impl Visitor<'_> for SubstringIndexOrderVisitor {
    fn visit_function_call_expr(&mut self, node: &'_ wirefilter::FunctionCallExpr) {
        if node.function().name() == "substring"
            && let [
                _,
                FunctionCallArgExpr::Literal(RhsValue::Int(start)),
                FunctionCallArgExpr::Literal(RhsValue::Int(end)),
            ] = node.args()
            && *start >= 0
            && *end >= 0
            && end < start
        {
            self.result.push(LintReport {
                id: LINT_NAME.into(),
                url: Some(create_url(LINT_NAME)),
                title: "Found inverted `substring()` indices".into(),
                message: format!(
                    "The end index ({end}) is less than the start index ({start}), so \
                     `substring()` returns an empty string. Ensure the end index is at least the \
                     start index, or use a negative index to count from the end."
                ),
                span: Span::ReverseByte(node.function().reverse_span.clone()),
            });
        }

        self.visit_value_expr(node);
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
    fn test_inverted_indices() {
        expect_lint_message(
            &LINTER,
            r#"substring(http.request.uri.path, 10, 5) eq "/api""#,
            expect![[r#"
                Found inverted `substring()` indices (substring_index_order)
                The end index (5) is less than the start index (10), so `substring()` returns an empty string. Ensure the end index is at least the start index, or use a negative index to count from the end."#]],
        );
    }

    #[test]
    fn test_negative_indices_are_not_flagged() {
        assert_value_no_lint_message(&LINTER, r#"substring(http.request.uri.path, -5, -10)"#);
        assert_value_no_lint_message(&LINTER, r#"substring(http.request.uri.path, -5, 2)"#);
        assert_value_no_lint_message(&LINTER, r#"substring(http.request.uri.path, 5, -2)"#);
    }

    #[test]
    fn test_ordered_or_unknown_indices_are_not_flagged() {
        assert_value_no_lint_message(&LINTER, "substring(http.request.uri.path, 5, 10)");
        assert_value_no_lint_message(&LINTER, "substring(http.request.uri.path, 5, 5)");
        assert_value_no_lint_message(&LINTER, "substring(http.request.uri.path, 5)");
    }
}
