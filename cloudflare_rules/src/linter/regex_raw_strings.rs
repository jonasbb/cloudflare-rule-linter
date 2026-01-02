use super::*;
use crate::ast_printer::AstPrintVisitor;
use wirefilter::{ComparisonExpr, ComparisonOpExpr, RegexFormat, Visitor};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct RegexRawStrings;
impl Lint for RegexRawStrings {
    fn name(&self) -> &'static str {
        "regex_raw_strings"
    }

    fn category(&self) -> Category {
        Category::Style
    }

    fn lint(&self, _config: &LinterConfig, ast: &FilterAst) -> Vec<LintReport> {
        // Ensure regex matches use raw string literals (r"...") instead of normal quoted strings
        struct RegexRawStringsVisitor {
            result: Vec<LintReport>,
        }
        let mut visitor = RegexRawStringsVisitor {
            result: Vec::new(),
        };

        impl Visitor<'_> for RegexRawStringsVisitor {
            fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
                if let ComparisonOpExpr::Matches(regex) = &node.op
                    && regex.format() == RegexFormat::Literal
                {
                    let node_str = AstPrintVisitor::comparison_expr_to_string(node);
                    self.result.push(LintReport {
                        id: "regex_raw_strings".into(),
                        url: None,
                        title: "Found regex match with non-raw string".into(),
                        message: format!(
                            "Regex matches must use raw string literals (e.g., r\"...\" or \
                             r#\"...\"#) when using the `matches` operator.",
                        ),
                        span_start: None,
                        span_end: None,
                    });
                }

                self.visit_value_expr(&node.lhs);
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
        linter.config.lints.enable_lints = vec![RegexRawStrings.name().into()];
        linter
    });

    #[test]
    fn test_regex_literal_warns() {
        expect_lint_message(
            &LINTER,
            r#"http.host matches ".*example.*""#,
            expect![[r##"
                Found regex match with non-raw string (regex_raw_strings)
                Regex matches must use raw string literals (e.g., r"..." or r#"..."#) when using the `matches` operator."##]],
        );
    }

    #[test]
    fn test_regex_raw_no_warn() {
        assert_no_lint_message(&LINTER, r#"http.host matches r".*example.*""#);
    }
}
