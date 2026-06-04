use super::*;
use wirefilter::Visitor;

static LINT_NAME: &str = "replace_functions_limit";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "regex_ and wildcard_replace functions are only allowed once and not nested.",
        category: Category::Correctness,
        lint_fn: lint,
        lint_value_fn: lint_value,
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = ReplaceFunctionVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

fn lint_value(_config: &LinterConfig, ast: &FilterValueAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = ReplaceFunctionVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

#[derive(Default)]
struct ReplaceFunctionVisitor {
    regex_counter: usize,
    regex_counter_total: usize,
    wildcard_counter: usize,
    wildcard_counter_total: usize,
    result: Vec<LintReport>,
}

impl Visitor<'_> for ReplaceFunctionVisitor {
    fn visit_function_call_expr(&mut self, node: &'_ wirefilter::FunctionCallExpr) {
        if node.function().name() == "regex_replace" {
            self.regex_counter += 1;
            self.regex_counter_total += 1;
            if self.wildcard_counter > 0 {
                self.result.push(LintReport {
                    id: LINT_NAME.into(),
                    url: None,
                    title: "Nested regex_replace functions are not allowed.".into(),
                    message: "The function `regex_replace` is not allowed to be nested inside \
                              another `wildcard_replace` function."
                        .into(),
                    span: Span::ReverseByte(node.function().reverse_span.clone()),
                });
            }
            if self.regex_counter_total > 1 {
                self.result.push(LintReport {
                    id: LINT_NAME.into(),
                    url: None,
                    title: "Multiple regex_replace functions are not allowed.".into(),
                    message: "The function `regex_replace` is only allowed to be used once in a \
                              filter expression."
                        .into(),
                    span: Span::ReverseByte(node.function().reverse_span.clone()),
                });
            }
            self.visit_value_expr(node);
            self.regex_counter -= 1;
        } else if node.function().name() == "wildcard_replace" {
            self.wildcard_counter += 1;
            self.wildcard_counter_total += 1;
            if self.regex_counter > 0 {
                self.result.push(LintReport {
                    id: LINT_NAME.into(),
                    url: None,
                    title: "Nested wildcard_replace functions are not allowed.".into(),
                    message: "The function `wildcard_replace` is not allowed to be nested inside \
                              another `regex_replace` function."
                        .into(),
                    span: Span::ReverseByte(node.function().reverse_span.clone()),
                });
            }
            if self.wildcard_counter_total > 1 {
                self.result.push(LintReport {
                    id: LINT_NAME.into(),
                    url: None,
                    title: "Multiple wildcard_replace functions are not allowed.".into(),
                    message: "The function `wildcard_replace` is only allowed to be used once in \
                              a filter expression."
                        .into(),
                    span: Span::ReverseByte(node.function().reverse_span.clone()),
                });
            }
            self.visit_value_expr(node);
            self.wildcard_counter -= 1;
        } else {
            self.visit_value_expr(node);
        }
    }
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
    fn test_single_regex_replace() {
        assert_value_no_lint_message(&LINTER, r#"regex_replace(http.host, r"www\.", "")"#);
    }

    #[test]
    fn test_single_wildcard_replace() {
        assert_value_no_lint_message(&LINTER, r#"wildcard_replace(http.host, "*.", "")"#);
    }

    #[test]
    fn test_single_regex_plus_wildcard_replace() {
        assert_value_no_lint_message(
            &LINTER,
            r#"concat(regex_replace(http.host, r"www\.", ""), wildcard_replace(http.host, "*.", ""))"#,
        );
    }

    #[test]
    fn test_two_regex_replace() {
        expect_value_lint_message(
            &LINTER,
            r#"concat(regex_replace(http.host, r"www\.", ""), regex_replace(http.host, r"www\.", ""))"#,
            expect![[r#"
                Multiple regex_replace functions are not allowed. (replace_functions_limit)
                The function `regex_replace` is only allowed to be used once in a filter expression."#]],
        );
        expect_value_lint_message(
            &LINTER,
            r#"regex_replace(regex_replace(http.host, r"www\.", ""), r"example\.", "")"#,
            expect![[r#"
                Multiple regex_replace functions are not allowed. (replace_functions_limit)
                The function `regex_replace` is only allowed to be used once in a filter expression."#]],
        );
    }

    #[test]
    fn test_two_wildcard_replace() {
        expect_value_lint_message(
            &LINTER,
            r#"concat(wildcard_replace(http.host, "*.", ""), wildcard_replace(http.host, "*.", ""))"#,
            expect![[r#"
                Multiple wildcard_replace functions are not allowed. (replace_functions_limit)
                The function `wildcard_replace` is only allowed to be used once in a filter expression."#]],
        );
        expect_value_lint_message(
            &LINTER,
            r#"wildcard_replace(wildcard_replace(http.host, "*.", ""), "*.", "")"#,
            expect![[r#"
                Multiple wildcard_replace functions are not allowed. (replace_functions_limit)
                The function `wildcard_replace` is only allowed to be used once in a filter expression."#]],
        );
    }

    #[test]
    fn test_nested_regex_and_wildcard_replace() {
        expect_value_lint_message(
            &LINTER,
            r#"regex_replace(wildcard_replace(http.host, "*.", ""), r"www\.", "")"#,
            expect![[r#"
                Nested wildcard_replace functions are not allowed. (replace_functions_limit)
                The function `wildcard_replace` is not allowed to be nested inside another `regex_replace` function."#]],
        );
        expect_value_lint_message(
            &LINTER,
            r#"wildcard_replace(regex_replace(http.host, r"www\.", ""), "*.", "")"#,
            expect![[r#"
                Nested regex_replace functions are not allowed. (replace_functions_limit)
                The function `regex_replace` is not allowed to be nested inside another `wildcard_replace` function."#]],
        );
    }
}
