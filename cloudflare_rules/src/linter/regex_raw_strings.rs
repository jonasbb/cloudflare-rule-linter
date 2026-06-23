use super::*;
use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, IdentifierExpr, RegexFormat, RhsValue, Visitor,
};

static LINT_NAME: &str = "regex_raw_strings";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Ensure regex matches use raw string literals (r\"...\") instead of normal quoted strings.",
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

/// Ensure regex matches use raw string literals (r"...") instead of normal quoted strings
#[derive(Default)]
struct RegexRawStringsVisitor {
    result: Vec<LintReport>,
}

impl Visitor<'_> for RegexRawStringsVisitor {
    fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
        if let ComparisonOpExpr::Matches(regex) = &node.op
                    && regex.format() == RegexFormat::Literal
                    // Only lint if any escaping is necessary
                    && regex.as_str().contains('\\')
        {
            self.result.push(LintReport {
                id: LINT_NAME.into(),
                url: Some(create_url(LINT_NAME)),
                title: "Found regex match with non-raw string".into(),
                message: "Regex matches must use raw string literals (e.g., r\"...\" or \
                          r#\"...\"#) when using the `matches` operator."
                    .to_string(),
                span: Span::ReverseByte(node.reverse_span.clone()),
            });
        }

        self.visit_expr(node);
    }

    fn visit_index_expr(&mut self, node: &'_ wirefilter::IndexExpr) {
        // Could be written with visit_function_call_expr but that doesn't have access to a reverse_span

        // Only lint if any escaping is necessary
        if let IdentifierExpr::FunctionCallExpr(func) = node.identifier()
            && func.function().name() == "regex_replace"
            && let [
                _field,
                wirefilter::FunctionCallArgExpr::Literal(RhsValue::Bytes(regex)),
                _replacement,
            ] = func.args()
            && !matches!(regex.format(), wirefilter::BytesFormat::Raw(_))
            && regex.contains(&b'\\')
        {
            self.result.push(LintReport {
                id: LINT_NAME.into(),
                url: Some(create_url(LINT_NAME)),
                title: "Found regex match with non-raw string".into(),
                message: "Regex matches must use raw string literals (e.g., r\"...\" or \
                          r#\"...\"#) when using the `matches` operator."
                    .to_string(),
                span: Span::ReverseByte(node.reverse_span.clone()),
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
    fn test_regex_literal_warns() {
        expect_lint_message(
            &LINTER,
            r#"http.host matches ".*example\.com""#,
            expect![[r##"
                Found regex match with non-raw string (regex_raw_strings)
                Regex matches must use raw string literals (e.g., r"..." or r#"..."#) when using the `matches` operator."##]],
        );
    }

    #[test]
    fn test_regex_raw_no_warn() {
        assert_no_lint_message(&LINTER, r#"http.host matches r".*example.*""#);
    }

    #[test]
    fn test_regex_only_if_escapes() {
        assert_no_lint_message(&LINTER, r#"http.host matches "example""#);
    }
}
