use super::*;
use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, ComparisonRhs, IdentifierExpr, LiteralSet, LiteralValue,
    OrderingOp, Visitor,
};

static LINT_NAME: &str = "hostname_suffix";

const HOSTNAME_FIELDS: &[&str] = &[
    "http.host",
    "http.request.full_uri",
    "raw.http.request.full_uri",
];

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

fn hostname_for_field<'a>(field: &str, value: &'a str) -> Option<&'a str> {
    match field {
        "http.host" => hostname_from_authority(value),
        "http.request.full_uri" | "raw.http.request.full_uri" => {
            let (scheme, rest) = value.split_once("://")?;
            if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
                return None;
            }
            let authority = rest.split(['/', '?', '#']).next()?;
            hostname_from_authority(authority)
        }
        _ => None,
    }
}

fn hostname_from_authority(authority: &str) -> Option<&str> {
    let authority = authority.rsplit('@').next()?;
    let hostname = if authority.starts_with('[') {
        let closing_bracket = authority.find(']')?;
        &authority[..=closing_bracket]
    } else {
        authority.split(':').next()?
    };
    (!hostname.is_empty()).then_some(hostname)
}

fn has_valid_suffix(hostname: &str, suffix: &str) -> bool {
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    let dotted_suffix = format!(".{suffix}");

    hostname.eq_ignore_ascii_case(suffix)
        || (hostname.len() > dotted_suffix.len()
            && hostname
                .get(hostname.len() - dotted_suffix.len()..)
                .is_some_and(|hostname_suffix| {
                    hostname_suffix.eq_ignore_ascii_case(&dotted_suffix)
                }))
}

fn invalid_hostname(field: &str, value: &str, suffix: &str) -> bool {
    hostname_for_field(field, value).is_some_and(|hostname| !has_valid_suffix(hostname, suffix))
}

fn hostname_lint_report(
    field: &str,
    values: &[String],
    suffix: &str,
    plural: bool,
    span: Span,
) -> LintReport {
    let message = if !plural {
        format!(
            "The value `{}` is not a valid value for `{field}`. Valid values must end with \
             `{suffix}`.",
            values[0]
        )
    } else {
        format!(
            "The value(s) `{}` are not a valid value for `{field}`. Valid values must end with \
             `{suffix}`.",
            values.join(" ")
        )
    };

    LintReport {
        id: LINT_NAME.into(),
        url: Some(create_url(LINT_NAME)),
        title: format!("Found invalid value for `{field}`"),
        message,
        span,
    }
}

impl Visitor<'_> for HostnameSuffixVisitor<'_> {
    fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
        if let Some(hostname_suffix) = self.hostname_suffix
            && !hostname_suffix.is_empty()
        {
            let field_name = match &node.lhs.identifier {
                IdentifierExpr::Field(field)
                    if node.lhs.indexes.is_empty() && HOSTNAME_FIELDS.contains(&field.name()) =>
                {
                    Some(field.name())
                }
                _ => None,
            };

            match &node.op {
                ComparisonOpExpr::Ordering { op, rhs } => {
                    if let (
                        OrderingOp::Equal | OrderingOp::NotEqual,
                        ComparisonRhs::Literal(LiteralValue::Bytes(bytes)),
                    ) = (op, rhs)
                        && let Some(field) = field_name
                        && let Ok(value) = std::str::from_utf8(bytes)
                        && invalid_hostname(field, value, hostname_suffix)
                    {
                        self.result.push(hostname_lint_report(
                            field,
                            &[value.to_string()],
                            hostname_suffix,
                            false,
                            Span::ReverseByte(node.reverse_span.clone()),
                        ));
                    }
                }
                ComparisonOpExpr::OneOf(values) => {
                    if let Some(field) = field_name {
                        let mut invalids = Vec::new();

                        if let LiteralSet::Bytes(items) = values {
                            for b in items.iter() {
                                if let Ok(value) = std::str::from_utf8(b)
                                    && invalid_hostname(field, value, hostname_suffix)
                                {
                                    invalids.push(value.to_string());
                                }
                            }
                        }

                        if !invalids.is_empty() {
                            self.result.push(hostname_lint_report(
                                field,
                                &invalids,
                                hostname_suffix,
                                true,
                                Span::ReverseByte(node.reverse_span.clone()),
                            ));
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
        assert_no_lint_message(&l, r#"http.host eq "WWW.EXAMPLE.COM""#);

        expect_lint_message(
            &l,
            r#"http.host eq "example.org""#,
            expect![[r#"
                Found invalid value for `http.host` (hostname_suffix)
                The value `example.org` is not a valid value for `http.host`. Valid values must end with `example.com`.
                Expr: 🡆🡆http.host eq "example.org"🡄🡄"#]],
        );

        expect_lint_message(
            &l,
            r#"http.host in { "example.org" "www.example.org" }"#,
            expect![[r#"
                Found invalid value for `http.host` (hostname_suffix)
                The value(s) `example.org www.example.org` are not a valid value for `http.host`. Valid values must end with `example.com`.
                Expr: 🡆🡆http.host in { "example.org" "www.example.org" }🡄🡄"#]],
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
                The value `notexample.com` is not a valid value for `http.host`. Valid values must end with `example.com`.
                Expr: 🡆🡆http.host eq "notexample.com"🡄🡄"#]],
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
                The value `example.com` is not a valid value for `http.host`. Valid values must end with `foo.bar.example.com`.
                Expr: 🡆🡆http.host eq "example.com"🡄🡄"#]],
        );
    }

    #[test]
    fn test_hostname_suffix_in_urls_and_zone_names() {
        let mut l = Linter::new();
        l.config = LinterConfig::default_disable_all_lints();
        l.config.lints.enable_lints = vec![LINT_NAME.into()];
        l.config.settings.zone_suffix = Some("example.com".into());

        expect_lint_message(
            &l,
            r#"http.request.full_uri eq "https://www.example.org/path?query=value""#,
            expect![[r#"
                Found invalid value for `http.request.full_uri` (hostname_suffix)
                The value `https://www.example.org/path?query=value` is not a valid value for `http.request.full_uri`. Valid values must end with `example.com`.
                Expr: 🡆🡆http.request.full_uri eq "https://www.example.org/path?query=value"🡄🡄"#]],
        );
        assert_no_lint_message(
            &l,
            r#"http.request.full_uri eq "https://www.example.com:8443/path""#,
        );

        expect_lint_message(
            &l,
            r#"raw.http.request.full_uri eq "https://www.example.org/path?query=value""#,
            expect![[r#"
                Found invalid value for `raw.http.request.full_uri` (hostname_suffix)
                The value `https://www.example.org/path?query=value` is not a valid value for `raw.http.request.full_uri`. Valid values must end with `example.com`.
                Expr: 🡆🡆raw.http.request.full_uri eq "https://www.example.org/path?query=value"🡄🡄"#]],
        );
        assert_no_lint_message(
            &l,
            r#"raw.http.request.full_uri eq "https://www.example.com:8443/path""#,
        );

        assert_no_lint_message(
            &l,
            r#"http.request.full_uri eq "https://example.com/path?redirect=example.org""#,
        );
        assert_no_lint_message(&l, r#"http.referer eq "about:blank""#);
    }
}
