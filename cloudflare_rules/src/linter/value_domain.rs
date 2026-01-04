use super::*;
use std::collections::BTreeMap;
use std::sync::LazyLock;
use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, IdentifierExpr, OrderingOp, RhsValue, RhsValues, Visitor,
};

enum Domain {
    List(Vec<&'static str>),
    Validate(fn(&str) -> bool, &'static str),
    IntRange(i64, i64),
}

static VALUE_DOMAINS: LazyLock<BTreeMap<&'static str, Domain>> = LazyLock::new(|| {
    fn is_all_uppercase(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_uppercase())
    }
    fn is_all_lowercase(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase())
    }

    BTreeMap::from([
        (
            "ip.src.continent",
            Domain::List(vec!["AF", "AN", "AS", "EU", "NA", "OC", "SA", "T1"]),
        ),
        (
            "http.request.method",
            Domain::Validate(
                is_all_uppercase,
                "consist only of uppercase characters (e.g., \"GET\")",
            ),
        ),
        (
            "http.request.uri.path.extension",
            Domain::Validate(
                is_all_lowercase,
                "consist only of lowercase characters (e.g., \"html\")",
            ),
        ),
        (
            "ip.src.country",
            Domain::Validate(
                |s: &str| s.len() == 2 && s.chars().all(|c| c.is_ascii_uppercase()),
                "be a 2-letter uppercase ISO 3166-1 Alpha-2 country code (e.g., \"US\")",
            ),
        ),
        ("http.request.timestamp.msec", Domain::IntRange(0, 999)),
        ("cf.edge.server_port", Domain::IntRange(1, 65535)),
        ("cf.bot_management.score", Domain::IntRange(1, 99)),
    ])
});

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ValueDomain;

impl Lint for ValueDomain {
    fn name(&self) -> &'static str {
        "value_domain"
    }

    fn category(&self) -> Category {
        Category::Correctness
    }

    fn lint(&self, _config: &LinterConfig, ast: &FilterAst) -> Vec<LintReport> {
        struct ValueDomainVisitor {
            result: Vec<LintReport>,
        }

        let mut visitor = ValueDomainVisitor { result: Vec::new() };

        impl Visitor<'_> for ValueDomainVisitor {
            fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
                // Only consider Ordering and OneOf comparisons
                match &node.op {
                    ComparisonOpExpr::Ordering { op, rhs } => {
                        // Only consider equality/inequality comparisons
                        match (op, rhs) {
                            (OrderingOp::Equal | OrderingOp::NotEqual, RhsValue::Bytes(bytes)) => {
                                if let IdentifierExpr::Field(field) = &node.lhs.identifier
                                    && let Some(domain) = VALUE_DOMAINS.get(field.name())
                                    && let Ok(s) = std::str::from_utf8(&bytes.data)
                                {
                                    match domain {
                                        Domain::List(valids) => {
                                            if !valids.contains(&s) {
                                                self.result.push(LintReport {
                                                    id: "value_domain".into(),
                                                    url: None,
                                                    title: format!(
                                                        "Found invalid value for {}",
                                                        field.name()
                                                    ),
                                                    message: format!(
                                                        "The value `{}` is not a valid value for \
                                                         `{}`. Valid values are: {}.",
                                                        s,
                                                        field.name(),
                                                        valids.join(", ")
                                                    ),
                                                    span: Span::ReverseByte(
                                                        node.reverse_span.clone(),
                                                    ),
                                                });
                                            }
                                        }
                                        Domain::Validate(func, desc) => {
                                            if !func(s) {
                                                self.result.push(LintReport {
                                                    id: "value_domain".into(),
                                                    url: None,
                                                    title: format!(
                                                        "Found invalid value for {}",
                                                        field.name()
                                                    ),
                                                    message: format!(
                                                        "The value `{}` is not a valid value for \
                                                         `{}`. Values must {}.",
                                                        s,
                                                        field.name(),
                                                        desc
                                                    ),
                                                    span: Span::ReverseByte(
                                                        node.reverse_span.clone(),
                                                    ),
                                                });
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            (OrderingOp::Equal | OrderingOp::NotEqual, RhsValue::Int(iv)) => {
                                if let IdentifierExpr::Field(field) = &node.lhs.identifier
                                    && let Some(Domain::IntRange(min, max)) =
                                        VALUE_DOMAINS.get(field.name())
                                    && (iv < min || iv > max)
                                {
                                    self.result.push(LintReport {
                                        id: "value_domain".into(),
                                        url: None,
                                        title: format!("Found invalid value for {}", field.name()),
                                        message: format!(
                                            "The value `{}` is not a valid value for `{}`. Valid \
                                             values are between {} and {}.",
                                            iv,
                                            field.name(),
                                            min,
                                            max
                                        ),
                                        span: Span::ReverseByte(node.reverse_span.clone()),
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                    ComparisonOpExpr::OneOf(values) => {
                        if let IdentifierExpr::Field(field) = &node.lhs.identifier
                            && let Some(domain) = VALUE_DOMAINS.get(field.name())
                        {
                            let mut invalids = Vec::new();

                            match values {
                                RhsValues::Bytes(items) => {
                                    for b in items.iter() {
                                        if let Ok(s) = std::str::from_utf8(&b.data) {
                                            match domain {
                                                Domain::List(valids) => {
                                                    if !valids.contains(&s) {
                                                        invalids.push(s.to_string());
                                                    }
                                                }
                                                Domain::Validate(func, _desc) => {
                                                    if !func(s) {
                                                        invalids.push(s.to_string());
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                RhsValues::Int(int_ranges) => {
                                    for r in int_ranges.iter() {
                                        let range: std::ops::RangeInclusive<i64> = r.clone().into();
                                        if let Domain::IntRange(min, max) = domain
                                            && (range.start() < min || range.end() > max)
                                        {
                                            let s = if range.start() == range.end() {
                                                format!("{}", range.start())
                                            } else {
                                                format!("{}..{}", range.start(), range.end())
                                            };
                                            invalids.push(s);
                                        }
                                    }
                                }
                                _ => {}
                            }

                            if !invalids.is_empty() {
                                let msg = match domain {
                                    Domain::List(valids) => format!(
                                        "The value(s) `{}` are not valid for `{}`. Valid values \
                                         are: {}.",
                                        invalids.join(" "),
                                        field.name(),
                                        valids.join(", ")
                                    ),
                                    Domain::Validate(_func, desc) => format!(
                                        "The value(s) `{}` are not valid for `{}`. Values must {}.",
                                        invalids.join(" "),
                                        field.name(),
                                        desc
                                    ),
                                    Domain::IntRange(min, max) => format!(
                                        "The value(s) `{}` are not valid for `{}`. Valid values \
                                         are between {} and {}.",
                                        invalids.join(" "),
                                        field.name(),
                                        min,
                                        max
                                    ),
                                };

                                self.result.push(LintReport {
                                    id: "value_domain".into(),
                                    url: None,
                                    title: format!("Found invalid value(s) for {}", field.name()),
                                    message: msg,
                                    span: Span::ReverseByte(node.reverse_span.clone()),
                                });
                            }
                        }
                    }
                    _ => {}
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

    static LINTER: std::sync::LazyLock<Linter> = std::sync::LazyLock::new(|| {
        let mut linter = Linter::new();
        linter.config = LinterConfig::default_disable_all_lints();
        linter.config.lints.enable_lints = vec![ValueDomain.name().into()];
        linter
    });

    #[test]
    fn test_invalid_continent() {
        expect_lint_message(
            &LINTER,
            r#"ip.src.continent eq "XX""#,
            expect![[r#"
                Found invalid value for ip.src.continent (value_domain)
                The value `XX` is not a valid value for `ip.src.continent`. Valid values are: AF, AN, AS, EU, NA, OC, SA, T1."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"ip.src.continent in {"EU" "XX" "NA"}"#,
            expect![[r#"
                Found invalid value(s) for ip.src.continent (value_domain)
                The value(s) `XX` are not valid for `ip.src.continent`. Valid values are: AF, AN, AS, EU, NA, OC, SA, T1."#]],
        );

        assert_no_lint_message(&LINTER, r#"ip.src.continent eq "EU""#);
        assert_no_lint_message(&LINTER, r#"ip.src.continent in {"EU" "NA"}"#);
    }

    #[test]
    fn test_http_method_case() {
        // lowercase method should be flagged
        expect_lint_message(
            &LINTER,
            r#"http.request.method eq "get""#,
            expect![[r#"
                Found invalid value for http.request.method (value_domain)
                The value `get` is not a valid value for `http.request.method`. Values must consist only of uppercase characters (e.g., "GET")."#]],
        );

        // mixed list should flag the lowercase entry
        expect_lint_message(
            &LINTER,
            r#"http.request.method in {"GET" "post"}"#,
            expect![[r#"
                Found invalid value(s) for http.request.method (value_domain)
                The value(s) `post` are not valid for `http.request.method`. Values must consist only of uppercase characters (e.g., "GET")."#]],
        );

        // valid cases shouldn't trigger
        assert_no_lint_message(&LINTER, r#"http.request.method eq "GET""#);
        assert_no_lint_message(&LINTER, r#"http.request.method in {"GET" "POST"}"#);
    }

    #[test]
    fn test_uri_extension_case() {
        // uppercase extension should be flagged
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path.extension eq "HTML""#,
            expect![[r#"
                Found invalid value for http.request.uri.path.extension (value_domain)
                The value `HTML` is not a valid value for `http.request.uri.path.extension`. Values must consist only of lowercase characters (e.g., "html")."#]],
        );

        // mixed list should flag the uppercase entry
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path.extension in {"html" "CSS"}"#,
            expect![[r#"
                Found invalid value(s) for http.request.uri.path.extension (value_domain)
                The value(s) `CSS` are not valid for `http.request.uri.path.extension`. Values must consist only of lowercase characters (e.g., "html")."#]],
        );

        // valid cases shouldn't trigger
        assert_no_lint_message(&LINTER, r#"http.request.uri.path.extension eq "html""#);
        assert_no_lint_message(
            &LINTER,
            r#"http.request.uri.path.extension in {"html" "css"}"#,
        );
    }

    #[test]
    fn test_country() {
        // ip.src.country (2-letter uppercase ISO alpha-2)
        expect_lint_message(
            &LINTER,
            r#"ip.src.country eq "us""#,
            expect![[r#"
                Found invalid value for ip.src.country (value_domain)
                The value `us` is not a valid value for `ip.src.country`. Values must be a 2-letter uppercase ISO 3166-1 Alpha-2 country code (e.g., "US")."#]],
        );

        expect_lint_message(
            &LINTER,
            r#"ip.src.country in {"US" "xx"}"#,
            expect![[r#"
                Found invalid value(s) for ip.src.country (value_domain)
                The value(s) `xx` are not valid for `ip.src.country`. Values must be a 2-letter uppercase ISO 3166-1 Alpha-2 country code (e.g., "US")."#]],
        );

        assert_no_lint_message(&LINTER, r#"ip.src.country eq "US""#);
    }

    #[test]
    fn test_timestamp_msec() {
        // http.request.timestamp.msec (0..999)
        expect_lint_message(
            &LINTER,
            r#"http.request.timestamp.msec eq 1000"#,
            expect![[r#"
                Found invalid value for http.request.timestamp.msec (value_domain)
                The value `1000` is not a valid value for `http.request.timestamp.msec`. Valid values are between 0 and 999."#]],
        );

        expect_lint_message(
            &LINTER,
            r#"http.request.timestamp.msec in {0 1000}"#,
            expect![[r#"
                Found invalid value(s) for http.request.timestamp.msec (value_domain)
                The value(s) `1000` are not valid for `http.request.timestamp.msec`. Valid values are between 0 and 999."#]],
        );

        assert_no_lint_message(&LINTER, r#"http.request.timestamp.msec eq 0"#);
        assert_no_lint_message(&LINTER, r#"http.request.timestamp.msec eq 999"#);
    }

    #[test]
    fn test_port() {
        // cf.edge.server_port (1..65535)
        expect_lint_message(
            &LINTER,
            r#"cf.edge.server_port eq 0"#,
            expect![[r#"
                Found invalid value for cf.edge.server_port (value_domain)
                The value `0` is not a valid value for `cf.edge.server_port`. Valid values are between 1 and 65535."#]],
        );

        expect_lint_message(
            &LINTER,
            r#"cf.edge.server_port in {80 70000}"#,
            expect![[r#"
                Found invalid value(s) for cf.edge.server_port (value_domain)
                The value(s) `70000` are not valid for `cf.edge.server_port`. Valid values are between 1 and 65535."#]],
        );

        assert_no_lint_message(&LINTER, r#"cf.edge.server_port eq 80"#);
    }

    #[test]
    fn test_bot_score() {
        // cf.bot_management.score (1..99)
        expect_lint_message(
            &LINTER,
            r#"cf.bot_management.score eq 0"#,
            expect![[r#"
                Found invalid value for cf.bot_management.score (value_domain)
                The value `0` is not a valid value for `cf.bot_management.score`. Valid values are between 1 and 99."#]],
        );

        expect_lint_message(
            &LINTER,
            r#"cf.bot_management.score in {1 100}"#,
            expect![[r#"
                Found invalid value(s) for cf.bot_management.score (value_domain)
                The value(s) `100` are not valid for `cf.bot_management.score`. Valid values are between 1 and 99."#]],
        );

        assert_no_lint_message(&LINTER, r#"cf.bot_management.score eq 1"#);
        assert_no_lint_message(&LINTER, r#"cf.bot_management.score eq 99"#);
    }
}
