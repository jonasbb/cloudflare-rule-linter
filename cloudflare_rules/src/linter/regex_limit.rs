use super::*;
use wirefilter::{ComparisonExpr, ComparisonOpExpr, IdentifierExpr, Visitor};

static LINT_NAME: &str = "regex_limit";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Check that a rule does not exceed the maximum number of regular expressions.",
        category: Category::Unskippable,
        lint_fn: lint,
        lint_value_fn: lint_value,
    }
}

fn lint(config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = RegexLimitVisitor::new(config.settings.regex_expression_limit);
    ast.walk(&mut visitor);
    visitor.result
}

fn lint_value(config: &LinterConfig, ast: &FilterValueAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = RegexLimitVisitor::new(config.settings.regex_expression_limit);
    ast.walk(&mut visitor);
    visitor.result
}

struct RegexLimitVisitor {
    limit: usize,
    count: usize,
    result: Vec<LintReport>,
}

impl RegexLimitVisitor {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            count: 0,
            result: Vec::new(),
        }
    }

    fn count_regex(&mut self, span: std::ops::Range<usize>) {
        self.count += 1;
        if self.count == self.limit.saturating_add(1) {
            self.result.push(LintReport {
                id: LINT_NAME.into(),
                url: Some(create_url(LINT_NAME)),
                title: "Too many regular expressions in rule".into(),
                message: format!(
                    "The rule contains more than {} regular expressions. Cloudflare allows at \
                     most {} per rule and will refuse to create or update it.",
                    self.limit, self.limit
                ),
                span: Span::ReverseByte(span),
            });
        }
    }
}

impl Visitor<'_> for RegexLimitVisitor {
    fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
        if let ComparisonOpExpr::Matches(_) = &node.op {
            self.count_regex(node.reverse_span.clone());
        }
        self.visit_expr(node);
    }

    fn visit_index_expr(&mut self, node: &'_ wirefilter::IndexExpr) {
        if let IdentifierExpr::FunctionCallExpr(func) = node.identifier()
            && func.function().name() == "regex_replace"
        {
            self.count_regex(node.reverse_span.clone());
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
    fn test_default_limit() {
        let expressions = (0..65)
            .map(|_| r#"http.host matches "example""#)
            .collect::<Vec<_>>()
            .join(" or ");
        expect_lint_message(
            &LINTER,
            &expressions,
            expect![[r#"
                Too many regular expressions in rule (regex_limit)
                The rule contains more than 64 regular expressions. Cloudflare allows at most 64 per rule and will refuse to create or update it."#]],
        );

        let expressions = (0..64)
            .map(|_| r#"http.host matches "example""#)
            .collect::<Vec<_>>()
            .join(" or ");
        assert_no_lint_message(&LINTER, &expressions);
    }

    #[test]
    fn test_configured_limit_counts_matches_and_regex_replace() {
        let mut linter = Linter::new();
        linter.config = LinterConfig::default_disable_all_lints();
        linter.config.lints.enable_lints = vec![LINT_NAME.into()];
        linter.config.settings.regex_expression_limit = 1;

        expect_lint_message(
            &linter,
            r#"http.host matches "example" and regex_replace(http.host, r"example", "") eq """#,
            expect![[r#"
                Too many regular expressions in rule (regex_limit)
                The rule contains more than 1 regular expressions. Cloudflare allows at most 1 per rule and will refuse to create or update it."#]],
        );
        assert_value_no_lint_message(&linter, r#"regex_replace(http.host, r"example", "")"#);
    }

    #[test]
    fn test_non_regex_patterns_are_not_counted() {
        assert_no_lint_message(&LINTER, r#"http.host wildcard "example*""#);
        assert_no_lint_message(&LINTER, r#"http.host eq "example""#);
        assert_value_no_lint_message(&LINTER, r#"wildcard_replace(http.host, "*", "")"#);
    }
}
