use super::*;
use wirefilter::{ComparisonExpr, ComparisonOpExpr, RhsValues, Visitor};

static LINT_NAME: &str = "empty_list";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Check for comparisons against empty lists, which are always false.",
        category: Category::Correctness,
        lint_fn: lint
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    struct EmptyListVisitor {
        result: Vec<LintReport>,
    }

    let mut visitor = EmptyListVisitor { result: Vec::new() };

    impl Visitor<'_> for EmptyListVisitor {
        fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
            // Only consider Ordering and OneOf comparisons
            if let ComparisonOpExpr::OneOf(rhs) = &node.op {
                let is_empty = match rhs {
                    RhsValues::Bool(_uninhabited_bool) => unreachable!(),
                    RhsValues::Int(ints) => ints.is_empty(),
                    RhsValues::Ip(ip_addrs) => ip_addrs.is_empty(),
                    RhsValues::Bytes(bytes) => bytes.is_empty(),
                    RhsValues::Array(_uninhabited_array) => unreachable!(),
                    RhsValues::Map(_uninhabited_map) => unreachable!(),
                };
                if is_empty {
                    self.result.push(LintReport {
                        id: LINT_NAME.into(),
                        url: Some(create_url(LINT_NAME)),
                        title: "Comparison with empty list are always false".to_string(),
                        message: "Consider removing the empty list or providing valid values."
                            .to_string(),
                        span: Span::ReverseByte(node.reverse_span.clone()),
                    });
                }
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
    fn test_empty_list() {
        expect_lint_message(
            &LINTER,
            r#"ip.src.continent in {}"#,
            expect![[r#"
                Comparison with empty list are always false (empty_list)
                Consider removing the empty list or providing valid values."#]],
        );

        assert_no_lint_message(&LINTER, r#"ip.src.continent in {"EU" "NA"}"#);
    }
}
