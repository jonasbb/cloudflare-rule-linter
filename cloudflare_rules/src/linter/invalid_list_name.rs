use super::*;
use wirefilter::{ComparisonExpr, ComparisonOpExpr, Visitor};

static LINT_NAME: &str = "invalid_list_name";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Check for invalid managed list names and optionally invalid custom list names.",
        category: Category::Correctness,
        lint_fn: lint
    }
}

fn lint(config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    // Ensure regex matches use raw string literals (r"...") instead of normal quoted strings
    struct InvalidListNameVisitor<'a> {
        result: Vec<LintReport>,
        /// If Some, a complete list of all custom lists that are allowed. If None, all custom lists are allowed.
        check_custom_lists: &'a Option<Vec<Box<str>>>,
    }
    let mut visitor = InvalidListNameVisitor {
        result: Vec::new(),
        check_custom_lists: &config.settings.invalid_list_name_custom_lists,
    };

    impl Visitor<'_> for InvalidListNameVisitor<'_> {
        fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
            if let ComparisonOpExpr::InList { list: _, name } = &node.op {
                // Taken from https://developers.cloudflare.com/waf/tools/lists/managed-lists/
                let predefined_lists = [
                    "cf.anonymizer",
                    "cf.botnetcc",
                    "cf.malware",
                    "cf.open_proxies",
                    "cf.vpn",
                ];
                if predefined_lists.contains(&name.as_str()) {
                    // Valid managed list name, do nothing
                } else if name.as_str().starts_with("cf.") || name.as_str().contains(".") {
                    self.result.push(LintReport {
                        id: LINT_NAME.into(),
                        url: Some(create_url(LINT_NAME)),
                        title: "Invalid managed list name".into(),
                        message: format!(
                            "Only the following managed list names are allowed: {}",
                            predefined_lists.join(", ")
                        ),
                        span: Span::ReverseByte(node.reverse_span.clone()),
                    });
                } else if let Some(custom_lists) = self.check_custom_lists
                    && custom_lists
                        .iter()
                        .all(|list| list.as_ref() != name.as_str())
                {
                    self.result.push(LintReport {
                        id: LINT_NAME.into(),
                        url: Some(create_url(LINT_NAME)),
                        title: "Invalid custom list name".into(),
                        message: format!(
                            "Custom list name `{}` is not in the allowed list of custom lists.",
                            name.as_str()
                        ),
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

    static LINTER: LazyLock<Linter> = LazyLock::new(|| {
        let mut linter = Linter::new();
        linter.config = LinterConfig::default_disable_all_lints();
        linter.config.lints.enable_lints = vec![LINT_NAME.into()];
        linter
    });

    #[test]
    fn test_invalid_list_name_managed_list() {
        expect_lint_message(
            &LINTER,
            r#"ip.src in $cf.bot"#,
            expect![[r#"
                Invalid managed list name (invalid_list_name)
                Only the following managed list names are allowed: cf.anonymizer, cf.botnetcc, cf.malware, cf.open_proxies, cf.vpn"#]],
        );

        assert_no_lint_message(&LINTER, r#"ip.src in $cf.vpn"#);
    }

    #[test]
    fn test_invalid_list_name_custom_list() {
        assert_no_lint_message(&LINTER, r#"ip.src in $unknown_list_name"#);
    }

    #[test]
    fn test_invalid_list_name_custom_list_with_config() {
        let mut config = LINTER.config.clone();
        config.settings.invalid_list_name_custom_lists = Some(vec!["allowed_list".into()]);
        let linter = Linter::with_config(config);
        expect_lint_message(
            &linter,
            r#"ip.src in $unknown_list_name"#,
            expect![[r#"
            Invalid custom list name (invalid_list_name)
            Custom list name `unknown_list_name` is not in the allowed list of custom lists."#]],
        );

        assert_no_lint_message(&linter, r#"ip.src in $allowed_list"#);
        assert_no_lint_message(&linter, r#"ip.src in $allowed_list or ip.src in $cf.vpn"#);
    }
}
