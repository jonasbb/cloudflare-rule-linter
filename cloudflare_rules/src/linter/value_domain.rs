use super::*;
use std::collections::BTreeMap;
use std::sync::LazyLock;
use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, IdentifierExpr, OrderingOp, RhsValue, RhsValues, Visitor,
};

// Some other useful checks
// https://github.com/doctena-org/octorules-cloudflare/blob/ac57450/docs/lint/stage2-per-rule.md#cf532--invalid-value-for-field-domain
enum Domain {
    List(Vec<&'static str>),
    /// Validation function and error message. The error message must complete the sentence "Values must ..."
    Validate(fn(&str) -> bool, &'static str),
    IntRange(i64, i64),
}

static VALUE_DOMAINS: LazyLock<BTreeMap<&'static str, Domain>> = LazyLock::new(|| {
    fn is_file_extension(s: &str) -> bool {
        s.chars().all(|c| !c.is_uppercase() && c != '.' && c != '/')
    }
    fn is_mime_type(s: &str) -> bool {
        !s.is_empty() && s.is_ascii() && s.contains('/') && s.chars().all(|c| !c.is_uppercase())
    }

    let field_definitions = [
        (
            "cf.bot_management.ja3_hash",
            Domain::Validate(
                |s: &str| {
                    s.is_empty() || (s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()))
                },
                "be a 32-character hexadecimal string or be empty",
            ),
        ),
        (
            "cf.bot_management.ja4",
            Domain::Validate(
                |s: &str| {
                    s.is_empty()
                        || (s.len() == 36
                            && s.chars()
                                .all(|c| c.is_ascii_alphabetic() || c.is_ascii_digit() || c == '_'))
                },
                "be a 36-character string or be empty",
            ),
        ),
        ("cf.bot_management.score", Domain::IntRange(1, 99)),
        ("cf.edge.server_port", Domain::IntRange(1, 65535)),
        (
            "cf.fraud.email_risk",
            Domain::List(vec!["unknown", "low", "medium", "high"]),
        ),
        ("cf.llm.prompt.injection_score", Domain::IntRange(1, 100)),
        (
            "cf.response.error_type",
            Domain::List(vec![
                // Empty is the default value
                "",
                "1xxx",
                "5xx",
                "always_online",
                "country_challenge",
                "ip_ban",
                "iuam",
                "legacy_challenge",
                "managed_challenge",
                "ratelimit",
                "waf",
            ]),
        ),
        (
            "cf.tls_version",
            Domain::List(vec!["", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]),
        ),
        ("cf.waf.score", Domain::IntRange(1, 100)),
        (
            "cf.waf.score.class",
            Domain::List(vec!["attack", "likely_attack", "likely_clean", "clean"]),
        ),
        ("cf.waf.score.rce", Domain::IntRange(1, 99)),
        ("cf.waf.score.sqli", Domain::IntRange(1, 99)),
        ("cf.waf.score.xss", Domain::IntRange(1, 99)),
        (
            "http.host",
            Domain::Validate(
                |s: &str| -> bool { !s.contains('/') },
                "follow the pattern <host> or <host>:<port>",
            ),
        ),
        (
            "http.request.body.mime",
            Domain::Validate(
                is_mime_type,
                "be a mime-type with lowercase characters (e.g., \"image/png\")",
            ),
        ),
        (
            "http.request.full_uri",
            Domain::Validate(
                |s: &str| -> bool { s.starts_with("http://") || s.starts_with("https://") },
                "start with \"http://\" or \"https://\"",
            ),
        ),
        (
            // https://www.iana.org/assignments/http-methods/http-methods.xhtml
            "http.request.method",
            Domain::List(vec![
                // The standard HTTP methods as listed on https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods
                "GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE", "CONNECT", "TRACE", "PATCH",
                // New RFC 10008 method https://datatracker.ietf.org/doc/rfc10008/
                "QUERY",
            ]),
        ),
        ("http.request.timestamp.msec", Domain::IntRange(0, 999)),
        (
            "http.request.uri.path",
            Domain::Validate(
                |s: &str| -> bool { s.starts_with('/') && !s.contains('?') },
                "start with a slash (/) and not contain a question mark (?)",
            ),
        ),
        (
            // The lowercased file extension in the URI path without the dot (.) character
            "http.request.uri.path.extension",
            Domain::Validate(
                is_file_extension,
                "not contain dots (.) or slashes (/) and not contain uppercase characters (e.g., \
                 \"html\")",
            ),
        ),
        (
            "http.request.version",
            Domain::List(vec!["HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"]),
        ),
        (
            "http.response.content_type.media_type",
            Domain::Validate(
                is_mime_type,
                "be a mime-type with lowercase characters (e.g., \"image/png\")",
            ),
        ),
        (
            "ip.src.continent",
            Domain::List(vec!["AF", "AN", "AS", "EU", "NA", "OC", "SA", "T1"]),
        ),
        (
            "ip.src.country",
            Domain::Validate(
                |s: &str| s.len() == 2 && s.chars().all(|c| c.is_ascii_uppercase()),
                "be a 2-letter uppercase ISO 3166-1 Alpha-2 country code (e.g., \"US\")",
            ),
        ),
        (
            "raw.http.request.full_uri",
            Domain::Validate(
                |s: &str| -> bool { s.starts_with("http://") || s.starts_with("https://") },
                "start with \"http://\" or \"https://\"",
            ),
        ),
        (
            "raw.http.request.uri.path",
            Domain::Validate(
                |s: &str| -> bool { s.starts_with('/') && !s.contains('?') },
                "start with a slash (/) and not contain a question mark (?)",
            ),
        ),
        (
            // The lowercased file extension in the URI path without the dot (.) character
            "raw.http.request.uri.path.extension",
            Domain::Validate(
                is_file_extension,
                "not contain dots (.) or slashes (/) and not contain uppercase characters (e.g., \
                 \"html\")",
            ),
        ),
    ];
    // Check that the field names are unique and sorted
    field_definitions
        .iter()
        .fold(None, |prev: Option<&str>, (field, _)| {
            if let Some(prev) = prev {
                assert!(
                    prev < *field,
                    "Field names must be unique and sorted: `{prev}` >= `{field}`"
                );
            }
            Some(*field)
        });
    BTreeMap::from(field_definitions)
});

static LINT_NAME: &str = "value_domain";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Check for values that are outside of the valid domain for certain fields, such as invalid HTTP methods or invalid continents.",
        category: Category::Correctness,
        lint_fn: lint,
        lint_value_fn: lint_value,
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = ValueDomainVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

fn lint_value(_config: &LinterConfig, ast: &FilterValueAst, _expr: &str) -> Vec<LintReport> {
    let mut visitor = ValueDomainVisitor::default();
    ast.walk(&mut visitor);
    visitor.result
}

#[derive(Default)]
struct ValueDomainVisitor {
    result: Vec<LintReport>,
}

impl Visitor<'_> for ValueDomainVisitor {
    fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
        // Only consider Ordering and OneOf comparisons
        match &node.op {
            ComparisonOpExpr::Ordering { op, rhs } => {
                // Only consider equality/inequality and pertinent ordering comparisons
                match (op, rhs) {
                    (OrderingOp::Equal | OrderingOp::NotEqual, RhsValue::Bytes(bytes)) => {
                        // Field equality checks (existing domain checks)
                        if let IdentifierExpr::Field(field) = &node.lhs.identifier
                            && node.lhs.indexes.is_empty()
                            && let Some(domain) = VALUE_DOMAINS.get(field.name())
                            && let Ok(s) = std::str::from_utf8(&bytes.data)
                        {
                            match domain {
                                Domain::List(valids) if !valids.contains(&s) => {
                                    self.result.push(LintReport {
                                        id: LINT_NAME.into(),
                                        url: Some(create_url(LINT_NAME)),
                                        title: format!("Found invalid value for {}", field.name()),
                                        message: format!(
                                            "The value `{}` is not a valid value for `{}`. Valid \
                                             values are: {}.",
                                            s,
                                            field.name(),
                                            valids.join(", ")
                                        ),
                                        span: Span::ReverseByte(node.reverse_span.clone()),
                                    });
                                }
                                Domain::Validate(func, desc) if !func(s) => {
                                    self.result.push(LintReport {
                                        id: LINT_NAME.into(),
                                        url: Some(create_url(LINT_NAME)),
                                        title: format!("Found invalid value for {}", field.name()),
                                        message: format!(
                                            "The value `{}` is not a valid value for `{}`. Values \
                                             must {}.",
                                            s,
                                            field.name(),
                                            desc
                                        ),
                                        span: Span::ReverseByte(node.reverse_span.clone()),
                                    });
                                }
                                _ => {}
                            }
                        }
                        // Function call checks (lower/upper)
                        else if let IdentifierExpr::FunctionCallExpr(call) = &node.lhs.identifier
                            && let Ok(s) = std::str::from_utf8(&bytes.data)
                        {
                            let name = call.function().name();
                            let fname_lbl = format!("{}(...)", name);
                            if name == "lower" && s.chars().any(|c| c.is_ascii_uppercase()) {
                                self.result.push(LintReport {
                                    id: LINT_NAME.into(),
                                    url: Some(create_url(LINT_NAME)),
                                    title: format!("Found invalid value for {}(...)", name),
                                    message: format!(
                                        "The value `{}` is not a valid value for `{}`. Values \
                                         must not contain uppercase ASCII characters.",
                                        s, fname_lbl
                                    ),
                                    span: Span::ReverseByte(node.reverse_span.clone()),
                                });
                            } else if name == "upper" && s.chars().any(|c| c.is_ascii_lowercase()) {
                                self.result.push(LintReport {
                                    id: LINT_NAME.into(),
                                    url: Some(create_url(LINT_NAME)),
                                    title: format!("Found invalid value for {}(...)", name),
                                    message: format!(
                                        "The value `{}` is not a valid value for `{}`. Values \
                                         must not contain lowercase ASCII characters.",
                                        s, fname_lbl
                                    ),
                                    span: Span::ReverseByte(node.reverse_span.clone()),
                                });
                            }
                        }
                    }
                    (OrderingOp::Equal | OrderingOp::NotEqual, RhsValue::Int(iv)) => {
                        if let IdentifierExpr::Field(field) = &node.lhs.identifier
                            && node.lhs.indexes.is_empty()
                            && let Some(Domain::IntRange(min, max)) =
                                VALUE_DOMAINS.get(field.name())
                            && (iv < min || iv > max)
                        {
                            self.result.push(LintReport {
                                id: LINT_NAME.into(),
                                url: Some(create_url(LINT_NAME)),
                                title: format!("Found invalid value for {}", field.name()),
                                message: format!(
                                    "The value `{}` is not a valid value for `{}`. Valid values \
                                     are between {} and {}.",
                                    iv,
                                    field.name(),
                                    min,
                                    max
                                ),
                                span: Span::ReverseByte(node.reverse_span.clone()),
                            });
                        } else if let IdentifierExpr::FunctionCallExpr(call) = &node.lhs.identifier
                            && call.function().name() == "len"
                            && *iv < 0
                        {
                            self.result.push(LintReport {
                                id: LINT_NAME.into(),
                                url: Some(create_url(LINT_NAME)),
                                title: "Found invalid value for len(...)".into(),
                                message: format!(
                                    "The value `{}` are not valid for `{}`. Values must be >= 0.",
                                    iv, "len(...)"
                                ),
                                span: Span::ReverseByte(node.reverse_span.clone()),
                            });
                        }
                    }
                    (OrderingOp::LessThan, RhsValue::Int(iv)) => {
                        // len(...) < 0 is invalid (RHS == 0 means check for negative lengths)
                        if let IdentifierExpr::FunctionCallExpr(call) = &node.lhs.identifier
                            && call.function().name() == "len"
                            && *iv <= 0
                        {
                            self.result.push(LintReport {
                                id: LINT_NAME.into(),
                                url: Some(create_url(LINT_NAME)),
                                title: "Found invalid value for len(...)".into(),
                                message: format!(
                                    "The value `{}` are not valid for `{}`. Values must be >= 0.",
                                    iv, "len(...)"
                                ),
                                span: Span::ReverseByte(node.reverse_span.clone()),
                            });
                        }
                    }
                    (OrderingOp::LessThanEqual, RhsValue::Int(iv)) => {
                        // len(...) <= 0 should warn (RHS <= 0)
                        if let IdentifierExpr::FunctionCallExpr(call) = &node.lhs.identifier
                            && call.function().name() == "len"
                        {
                            if *iv == 0 {
                                self.result.push(LintReport {
                                    id: LINT_NAME.into(),
                                    url: Some(create_url(LINT_NAME)),
                                    title: "Found bad value for len(...)".into(),
                                    message: "len(...) can never be negative thus `lt 0` can be \
                                              simplified to `eq 0`."
                                        .to_string(),
                                    span: Span::ReverseByte(node.reverse_span.clone()),
                                });
                            } else if *iv < 0 {
                                self.result.push(LintReport {
                                    id: LINT_NAME.into(),
                                    url: Some(create_url(LINT_NAME)),
                                    title: "Found invalid value for len(...)".into(),
                                    message: format!(
                                        "The value `{}` are not valid for `{}`. Values must be >= \
                                         0.",
                                        iv, "len(...)"
                                    ),
                                    span: Span::ReverseByte(node.reverse_span.clone()),
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
            ComparisonOpExpr::OneOf(values) => {
                if let IdentifierExpr::Field(field) = &node.lhs.identifier
                    && node.lhs.indexes.is_empty()
                    && let Some(domain) = VALUE_DOMAINS.get(field.name())
                {
                    let mut invalids = Vec::new();

                    match values {
                        RhsValues::Bytes(items) => {
                            for b in items.iter() {
                                if let Ok(s) = std::str::from_utf8(&b.data) {
                                    match domain {
                                        Domain::List(valids) if !valids.contains(&s) => {
                                            invalids.push(s.to_string());
                                        }
                                        Domain::Validate(func, _desc) if !func(s) => {
                                            invalids.push(s.to_string());
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
                                "The value(s) `{}` are not valid for `{}`. Valid values are: {}.",
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
                                "The value(s) `{}` are not valid for `{}`. Valid values are \
                                 between {} and {}.",
                                invalids.join(" "),
                                field.name(),
                                min,
                                max
                            ),
                        };

                        self.result.push(LintReport {
                            id: LINT_NAME.into(),
                            url: Some(create_url(LINT_NAME)),
                            title: format!("Found invalid value(s) for {}", field.name()),
                            message: msg,
                            span: Span::ReverseByte(node.reverse_span.clone()),
                        });
                    }
                } else if let IdentifierExpr::FunctionCallExpr(call) = &node.lhs.identifier {
                    match values {
                        RhsValues::Bytes(items) => {
                            let name = call.function().name();
                            let mut invalids = Vec::new();
                            for b in items.iter() {
                                if let Ok(s) = std::str::from_utf8(&b.data)
                                    && ((name == "lower"
                                        && s.chars().any(|c| c.is_ascii_uppercase()))
                                        || (name == "upper"
                                            && s.chars().any(|c| c.is_ascii_lowercase())))
                                {
                                    invalids.push(s.to_string());
                                }
                            }
                            if !invalids.is_empty() {
                                let fname_lbl = format!("{}(...)", name);
                                let msg = if name == "lower" {
                                    format!(
                                        "The value(s) `{}` are not valid for `{}`. Values must \
                                         not contain uppercase ASCII characters.",
                                        invalids.join(" "),
                                        fname_lbl
                                    )
                                } else {
                                    format!(
                                        "The value(s) `{}` are not valid for `{}`. Values must \
                                         not contain lowercase ASCII characters.",
                                        invalids.join(" "),
                                        fname_lbl
                                    )
                                };
                                self.result.push(LintReport {
                                    id: LINT_NAME.into(),
                                    url: Some(create_url(LINT_NAME)),
                                    title: format!("Found invalid value(s) for {}(...)", name),
                                    message: msg,
                                    span: Span::ReverseByte(node.reverse_span.clone()),
                                });
                            }
                        }
                        RhsValues::Int(int_ranges) if call.function().name() == "len" => {
                            let mut invalids = Vec::new();
                            for r in int_ranges.iter() {
                                let range: std::ops::RangeInclusive<i64> = r.clone().into();
                                if *range.start() < 0 || *range.end() < 0 {
                                    let s = if range.start() == range.end() {
                                        format!("{}", range.start())
                                    } else {
                                        format!("{}..{}", range.start(), range.end())
                                    };
                                    invalids.push(s);
                                }
                            }
                            if !invalids.is_empty() {
                                let msg = format!(
                                    "The value(s) `{}` are not valid for `{}`. Values must be >= \
                                     0.",
                                    invalids.join(" "),
                                    "len(...)"
                                );
                                self.result.push(LintReport {
                                    id: LINT_NAME.into(),
                                    url: Some(create_url(LINT_NAME)),
                                    title: "Found invalid value(s) for len(...)".into(),
                                    message: msg,
                                    span: Span::ReverseByte(node.reverse_span.clone()),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        self.visit_expr(node);
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
                The value `HTML` is not a valid value for `http.request.uri.path.extension`. Values must not contain dots (.) or slashes (/) and not contain uppercase characters (e.g., "html")."#]],
        );

        // mixed list should flag the uppercase entry
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path.extension in {"html" "CSS"}"#,
            expect![[r#"
                Found invalid value(s) for http.request.uri.path.extension (value_domain)
                The value(s) `CSS` are not valid for `http.request.uri.path.extension`. Values must not contain dots (.) or slashes (/) and not contain uppercase characters (e.g., "html")."#]],
        );

        // Dot in the extension should raise concerns
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path.extension eq ".html""#,
            expect![[r#"
                Found invalid value for http.request.uri.path.extension (value_domain)
                The value `.html` is not a valid value for `http.request.uri.path.extension`. Values must not contain dots (.) or slashes (/) and not contain uppercase characters (e.g., "html")."#]],
        );

        // valid cases shouldn't trigger
        assert_no_lint_message(&LINTER, r#"http.request.uri.path.extension eq "html""#);
        assert_no_lint_message(&LINTER, r#"http.request.uri.path.extension eq "mp3""#);
        assert_no_lint_message(
            &LINTER,
            r#"http.request.uri.path.extension in {"html" "css"}"#,
        );
        assert_no_lint_message(&LINTER, r#"raw.http.request.uri.path.extension eq """#);
        assert_no_lint_message(&LINTER, r#"raw.http.request.uri.path.extension eq "mp3""#);
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

    #[test]
    fn test_error_type() {
        expect_lint_message(
            &LINTER,
            r#"cf.response.error_type eq "sbfm""#,
            expect![[r#"
                Found invalid value for cf.response.error_type (value_domain)
                The value `sbfm` is not a valid value for `cf.response.error_type`. Valid values are: 1xxx, 5xx, always_online, country_challenge, ip_ban, iuam, legacy_challenge, managed_challenge, ratelimit, waf."#]],
        );

        assert_no_lint_message(&LINTER, r#"cf.response.error_type eq "waf""#);
    }

    #[test]
    fn test_waf_score_class() {
        expect_lint_message(
            &LINTER,
            r#"cf.waf.score.class eq "bot""#,
            expect![[r#"
                Found invalid value for cf.waf.score.class (value_domain)
                The value `bot` is not a valid value for `cf.waf.score.class`. Valid values are: attack, likely_attack, likely_clean, clean."#]],
        );

        assert_no_lint_message(&LINTER, r#"cf.waf.score.class eq "clean""#);
    }

    #[test]
    fn test_mime_type() {
        expect_lint_message(
            &LINTER,
            r#"http.request.body.mime eq "image""#,
            expect![[r#"
                Found invalid value for http.request.body.mime (value_domain)
                The value `image` is not a valid value for `http.request.body.mime`. Values must be a mime-type with lowercase characters (e.g., "image/png")."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.request.body.mime eq "Foo/Bar""#,
            expect![[r#"
                Found invalid value for http.request.body.mime (value_domain)
                The value `Foo/Bar` is not a valid value for `http.request.body.mime`. Values must be a mime-type with lowercase characters (e.g., "image/png")."#]],
        );

        assert_no_lint_message(&LINTER, r#"http.request.body.mime eq "image/bmp""#);
        assert_no_lint_message(
            &LINTER,
            r#"http.request.body.mime in {"image/bmp" "image/gif" "image/jpeg" "image/png" "image/tiff"}"#,
        );
        assert_no_lint_message(
            &LINTER,
            r#"http.request.body.mime eq "application/3gpp-media-delivery-metrics-report+json""#,
        );
    }

    #[test]
    fn test_content_media_type() {
        expect_lint_message(
            &LINTER,
            r#"http.response.content_type.media_type eq "text""#,
            expect![[r#"
                Found invalid value for http.response.content_type.media_type (value_domain)
                The value `text` is not a valid value for `http.response.content_type.media_type`. Values must be a mime-type with lowercase characters (e.g., "image/png")."#]],
        );

        assert_no_lint_message(
            &LINTER,
            r#"http.response.content_type.media_type eq "text/html+extra""#,
        );
    }

    #[test]
    fn test_http_version() {
        expect_lint_message(
            &LINTER,
            r#"http.request.version eq "3""#,
            expect![[r#"
                Found invalid value for http.request.version (value_domain)
                The value `3` is not a valid value for `http.request.version`. Values must start with "HTTP/"."#]],
        );

        assert_no_lint_message(
            &LINTER,
            r#"http.request.version in {"HTTP/0.9" "HTTP/1.0" "HTTP/1.1" "HTTP/2" "HTTP/3"}"#,
        );
    }

    #[test]
    fn test_lower_upper_functions() {
        // lower() result must not contain uppercase characters
        expect_lint_message(
            &LINTER,
            r#"lower(http.request.method) eq "GET""#,
            expect![[r#"
                Found invalid value for lower(...) (value_domain)
                The value `GET` is not a valid value for `lower(...)`. Values must not contain uppercase ASCII characters."#]],
        );

        expect_lint_message(
            &LINTER,
            r#"lower(http.request.method) in {"get" "POST"}"#,
            expect![[r#"
                Found invalid value(s) for lower(...) (value_domain)
                The value(s) `POST` are not valid for `lower(...)`. Values must not contain uppercase ASCII characters."#]],
        );

        // upper() result must not contain lowercase characters
        expect_lint_message(
            &LINTER,
            r#"upper(http.request.method) eq "get""#,
            expect![[r#"
                Found invalid value for upper(...) (value_domain)
                The value `get` is not a valid value for `upper(...)`. Values must not contain lowercase ASCII characters."#]],
        );

        expect_lint_message(
            &LINTER,
            r#"upper(http.request.method) in {"GET" "post"}"#,
            expect![[r#"
                Found invalid value(s) for upper(...) (value_domain)
                The value(s) `post` are not valid for `upper(...)`. Values must not contain lowercase ASCII characters."#]],
        );

        // valid cases shouldn't trigger
        assert_no_lint_message(&LINTER, r#"lower(http.request.method) eq "get""#);
        assert_no_lint_message(&LINTER, r#"upper(http.request.method) eq "GET""#);
    }

    #[test]
    fn test_len_non_negative() {
        // len(...) < 0 should warn
        expect_lint_message(
            &LINTER,
            r#"len(http.request.uri.path.extension) < 0"#,
            expect![[r#"
                Found invalid value for len(...) (value_domain)
                The value `0` are not valid for `len(...)`. Values must be >= 0."#]],
        );

        // len(...) <= 0 should warn
        expect_lint_message(
            &LINTER,
            r#"len(http.request.uri.path.extension) <= 0"#,
            expect![[r#"
                Found bad value for len(...) (value_domain)
                len(...) can never be negative thus `lt 0` can be simplified to `eq 0`."#]],
        );

        // len(...) eq -1 should warn
        expect_lint_message(
            &LINTER,
            r#"len(http.request.uri.path.extension) eq -1"#,
            expect![[r#"
                Found invalid value for len(...) (value_domain)
                The value `-1` are not valid for `len(...)`. Values must be >= 0."#]],
        );

        // len(...) in {-1 0} should flag -1
        expect_lint_message(
            &LINTER,
            r#"len(http.request.uri.path.extension) in {-1 0}"#,
            expect![[r#"
                Found invalid value(s) for len(...) (value_domain)
                The value(s) `-1` are not valid for `len(...)`. Values must be >= 0."#]],
        );

        // valid cases shouldn't trigger
        assert_no_lint_message(&LINTER, r#"len(http.request.uri.path.extension) eq 0"#);
        assert_no_lint_message(&LINTER, r#"len(http.request.uri.path.extension) lt 5"#);
    }

    #[test]
    fn test_path() {
        expect_lint_message(
            &LINTER,
            r#"http.request.uri.path eq "html""#,
            expect![[r#"
                Found invalid value for http.request.uri.path (value_domain)
                The value `html` is not a valid value for `http.request.uri.path`. Values must start with a slash (/) and not contain a question mark (?)."#]],
        );
        assert_no_lint_message(&LINTER, r#"http.request.uri.path eq "/""#);

        expect_lint_message(
            &LINTER,
            r#"raw.http.request.uri.path eq "html""#,
            expect![[r#"
                Found invalid value for raw.http.request.uri.path (value_domain)
                The value `html` is not a valid value for `raw.http.request.uri.path`. Values must start with a slash (/) and not contain a question mark (?)."#]],
        );
        assert_no_lint_message(&LINTER, r#"raw.http.request.uri.path eq "/""#);
    }

    #[test]
    fn test_full_uri() {
        expect_lint_message(
            &LINTER,
            r#"http.request.full_uri eq "www.example.com/foo/index.html""#,
            expect![[r#"
                Found invalid value for http.request.full_uri (value_domain)
                The value `www.example.com/foo/index.html` is not a valid value for `http.request.full_uri`. Values must start with "http://" or "https://"."#]],
        );
        assert_no_lint_message(
            &LINTER,
            r#"http.request.full_uri eq "http://example.com/foo/index.html""#,
        );
        assert_no_lint_message(
            &LINTER,
            r#"http.request.full_uri eq "https://example.com/""#,
        );

        expect_lint_message(
            &LINTER,
            r#"raw.http.request.full_uri eq "www.example.com/foo/index.html""#,
            expect![[r#"
                Found invalid value for raw.http.request.full_uri (value_domain)
                The value `www.example.com/foo/index.html` is not a valid value for `raw.http.request.full_uri`. Values must start with "http://" or "https://"."#]],
        );
        assert_no_lint_message(
            &LINTER,
            r#"raw.http.request.full_uri eq "http://example.com/foo/index.html""#,
        );
        assert_no_lint_message(
            &LINTER,
            r#"raw.http.request.full_uri eq "https://example.com/""#,
        );
    }

    #[test]
    fn test_ja_hashes() {
        assert_no_lint_message(
            &LINTER,
            r#"cf.bot_management.ja3_hash eq "e7d705a3286e19ea42f587b344ee6865""#,
        );
        assert_no_lint_message(
            &LINTER,
            r#"cf.bot_management.ja3_hash eq "6734f37431670b3ab4292b8f60f29984""#,
        );
        assert_no_lint_message(
            &LINTER,
            r#"cf.bot_management.ja4 eq "t13d1516h2_8daaf6152771_02713d6af862""#,
        );
    }
}
