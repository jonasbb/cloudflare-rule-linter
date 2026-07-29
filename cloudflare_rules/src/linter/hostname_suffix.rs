use super::*;
use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, IdentifierExpr, OrderingOp, RhsValue, RhsValues, Visitor,
};

static LINT_NAME: &str = "hostname_suffix";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Check for values that are outside of the valid domain for certain fields, such as invalid HTTP methods or invalid continents.",
        category: Category::Correctness,
        lint_fn: lint,
        lint_value_fn: lint_value,
    }
}

fn lint(config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = HostnameSuffixVisitor::new(config);
    ast.walk(&mut visitor);
    visitor.result
}

fn lint_value(config: &LinterConfig, ast: &FilterValueAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = HostnameSuffixVisitor::new(config);
    ast.walk(&mut visitor);
    visitor.result
}

#[derive(Default)]
struct HostnameSuffixVisitor<'a> {
    result: Vec<LintReport>,
    hostname_suffix: Option<&'a str>,
}

impl<'a> HostnameSuffixVisitor<'a> {
    fn new(config: &'a LinterConfig) -> Self {
        Self {
            result: Vec::new(),
            hostname_suffix: config.settings.zone_suffix.as_deref(),
        }
    }
}

impl Visitor<'_> for HostnameSuffixVisitor<'_> {
    fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
        if let Some(hostname_suffix) = self.hostname_suffix
            && !hostname_suffix.is_empty()
        {
            // Dotted suffix if for suffix matching, e.g. ".example.com" for "example.com"
            // This ensures there is a label boundary before the suffix, so that "notexample.com" does not match "example.com"
            let dotted_suffix = format!(".{hostname_suffix}");

            // Only consider Ordering and OneOf comparisons
            match &node.op {
                ComparisonOpExpr::Ordering { op, rhs } => {
                    // Only consider equality/inequality and pertinent ordering comparisons
                    if let (OrderingOp::Equal | OrderingOp::NotEqual, RhsValue::Bytes(bytes)) =
                        (op, rhs)
                    {
                        // Field equality checks (existing domain checks)
                        if let IdentifierExpr::Field(field) = &node.lhs.identifier
                            && node.lhs.indexes.is_empty()
                            && field.name() == "http.host"
                            && let Ok(host_literal) = std::str::from_utf8(&bytes.data)
                            && !(host_literal == hostname_suffix
                                || host_literal.ends_with(&dotted_suffix))
                        {
                            self.result.push(LintReport {
                                id: LINT_NAME.into(),
                                url: Some(create_url(LINT_NAME)),
                                title: "Found invalid value for `http.host`".to_string(),
                                message: format!(
                                    "The value `{}` is not a valid value for `http.host`. Valid \
                                     values must end with `{}`.",
                                    host_literal, hostname_suffix
                                ),
                                span: Span::ReverseByte(node.reverse_span.clone()),
                            });
                        }
                    }
                }
                ComparisonOpExpr::OneOf(values) => {
                    if let IdentifierExpr::Field(field) = &node.lhs.identifier
                        && node.lhs.indexes.is_empty()
                        && field.name() == "http.host"
                    {
                        let mut invalids = Vec::new();

                        if let RhsValues::Bytes(items) = values {
                            for b in items.iter() {
                                if let Ok(host_literal) = std::str::from_utf8(&b.data)
                                    && !(host_literal == hostname_suffix
                                        || host_literal.ends_with(&dotted_suffix))
                                {
                                    invalids.push(host_literal.to_string());
                                }
                            }
                        }

                        if !invalids.is_empty() {
                            self.result.push(LintReport {
                                id: LINT_NAME.into(),
                                url: Some(create_url(LINT_NAME)),
                                title: "Found invalid value for `http.host`".to_string(),
                                message: format!(
                                    "The value(s) `{}` are not a valid value for `http.host`. \
                                     Valid values must end with `{}`.",
                                    invalids.join(" "),
                                    hostname_suffix
                                ),
                                span: Span::ReverseByte(node.reverse_span.clone()),
                            });
                        }
                    }
                }
                _ => {}
            }

            self.visit_expr(node);
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
    fn test_hostname_no_config() {
        assert_no_lint_message(&LINTER, r#"http.host eq "INVALID""#);
        assert_no_lint_message(&LINTER, r#"http.host in {"INVALID" "INVALID2"}"#);
    }

    #[test]
    fn test_hostname_invalid_tld() {
        let mut l = Linter::new();
        l.config = LinterConfig::default_disable_all_lints();
        l.config.lints.enable_lints = vec![LINT_NAME.into()];
        l.config.settings.zone_suffix = Some("example.com".into());

        assert_no_lint_message(&l, r#"http.host eq "example.com""#);
        assert_no_lint_message(&l, r#"http.host in { "www.example.com" }"#);

        expect_lint_message(
            &l,
            r#"http.host eq "example.org""#,
            expect![[r#"
                Found invalid value for `http.host` (hostname_suffix)
                The value `example.org` is not a valid value for `http.host`. Valid values must end with `example.com`."#]],
        );

        expect_lint_message(
            &l,
            r#"http.host in { "example.org" "www.example.org" }"#,
            expect![[r#"
                Found invalid value for `http.host` (hostname_suffix)
                The value(s) `example.org www.example.org` are not a valid value for `http.host`. Valid values must end with `example.com`."#]],
        );
    }

    #[test]
    fn test_hostname_wrong_suffix_match() {
        let mut l = Linter::new();
        l.config = LinterConfig::default_disable_all_lints();
        l.config.lints.enable_lints = vec![LINT_NAME.into()];
        l.config.settings.zone_suffix = Some("example.com".into());

        expect_lint_message(
            &l,
            r#"http.host eq "notexample.com""#,
            expect![[r#"
                Found invalid value for `http.host` (hostname_suffix)
                The value `notexample.com` is not a valid value for `http.host`. Valid values must end with `example.com`."#]],
        );
    }

    #[test]
    fn test_hostname_too_short_hostname() {
        let mut l = Linter::new();
        l.config = LinterConfig::default_disable_all_lints();
        l.config.lints.enable_lints = vec![LINT_NAME.into()];
        l.config.settings.zone_suffix = Some("foo.bar.example.com".into());

        expect_lint_message(
            &l,
            r#"http.host eq "example.com""#,
            expect![[r#"
                Found invalid value for `http.host` (hostname_suffix)
                The value `example.com` is not a valid value for `http.host`. Valid values must end with `foo.bar.example.com`."#]],
        );
    }
}
