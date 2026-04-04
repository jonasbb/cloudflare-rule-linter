use super::*;
use std::sync::LazyLock;
use wirefilter::{
    ComparisonOpExpr, FieldIndex, IdentifierExpr, OrderingOp, RhsValue, RhsValues, Visitor,
};

static HEADER_MAP_FIELDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "http.request.headers",
        "http.response.headers",
        "raw.http.response.headers",
    ]
});
static HEADER_FIELDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "http.request.headers.names",
        "http.response.headers.names",
        "raw.http.response.headers.names",
    ]
});

static LINT_NAME: &str = "header_case";

inventory::submit! {
    Lint {
        name: LINT_NAME,
        description: "Checks for header names that are not all lowercase.",
        category: Category::Correctness,
        lint_fn: lint
    }
}

fn lint(_config: &LinterConfig, ast: &FilterAst, _expr: &str) -> Vec<LintReport> {
    struct MapKeyCaseVisitor {
        result: Vec<LintReport>,
    }

    let mut visitor = MapKeyCaseVisitor { result: Vec::new() };

    impl Visitor<'_> for MapKeyCaseVisitor {
        fn visit_comparison_expr(&mut self, node: &'_ wirefilter::ComparisonExpr) {
            if let IdentifierExpr::Field(field) = &node.lhs.identifier
                && !node.lhs.indexes.is_empty()
                && HEADER_FIELDS.contains(&field.name())
            {
                // Only consider Ordering and OneOf comparisons
                match &node.op {
                    ComparisonOpExpr::Ordering { op, rhs } => {
                        // Only consider equality/inequality comparisons
                        // The ".names" fields are lists that need to be indexed into
                        if let (OrderingOp::Equal | OrderingOp::NotEqual, RhsValue::Bytes(bytes)) =
                            (op, rhs)
                            && let Ok(header) = std::str::from_utf8(&bytes.data)
                            && header.chars().any(|c| c.is_ascii_uppercase())
                        {
                            self.result.push(LintReport {
                                id: LINT_NAME.into(),
                                url: Some(create_url(LINT_NAME)),
                                title: format!(
                                    "Found uppercase characters in header name `{}`",
                                    header
                                ),
                                message: format!(
                                    "Header names must always be all lowercase but `{}` contains \
                                     uppercase characters. It should be lowercase (e.g., \
                                     \"content-type\").",
                                    header
                                ),
                                span: Span::ReverseByte(node.reverse_span.clone()),
                            });
                        }
                    }
                    ComparisonOpExpr::OneOf(RhsValues::Bytes(items)) => {
                        // The ".names" fields are lists that need to be indexed into
                        for b in items.iter() {
                            if let Ok(header) = std::str::from_utf8(&b.data)
                                && header.chars().any(|c| c.is_ascii_uppercase())
                            {
                                self.result.push(LintReport {
                                    id: LINT_NAME.into(),
                                    url: Some(create_url(LINT_NAME)),
                                    title: format!(
                                        "Found uppercase characters in header name `{}`",
                                        header
                                    ),
                                    message: format!(
                                        "Header names must always be all lowercase but `{}` \
                                         contains uppercase characters. It should be lowercase \
                                         (e.g., \"content-type\").",
                                        header
                                    ),
                                    span: Span::ReverseByte(node.reverse_span.clone()),
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Continue walking the expression
            self.visit_expr(node);
        }

        fn visit_index_expr(&mut self, node: &'_ wirefilter::IndexExpr) {
            // Check the string used as map key for header fields
            // http.request.headers["content-type"][*]
            //                       ^^^^^^^^^^^^
            //
            // Only consider comparisons with an IndexExpr on the LHS
            // Only consider the header map fields we care about
            // Look at the first index only as that is the map key
            if let IdentifierExpr::Field(field) = &node.identifier
                && HEADER_MAP_FIELDS.contains(&field.name())
                && let [FieldIndex::MapKey(header), ..] = &node.indexes[..]
                && header.chars().any(|c| c.is_ascii_uppercase())
            {
                self.result.push(LintReport {
                    id: LINT_NAME.into(),
                    url: Some(create_url(LINT_NAME)),
                    title: format!("Found uppercase characters in header name `{}`", header),
                    message: format!(
                        "The map key `{}` used to index `{}` contains uppercase characters; keys \
                         should be lowercase (e.g., \"content-type\").",
                        header,
                        field.name()
                    ),
                    span: Span::ReverseByte(node.reverse_span.clone()),
                });
            }

            self.visit_value_expr(node);
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
    fn test_header_lowercase_is_ok() {
        assert_no_lint_message(
            &LINTER,
            r#"any(http.request.headers["content-type"][*] == "application/json")"#,
        );
        assert_no_lint_message(
            &LINTER,
            r#"any(http.response.headers["content-type"][*] == "application/json")"#,
        );
        assert_no_lint_message(
            &LINTER,
            r#"any(raw.http.response.headers["content-type"][*] == "application/json")"#,
        );
    }

    #[test]
    fn test_header_uppercase_warns() {
        expect_lint_message(
            &LINTER,
            r#"any(http.request.headers["Authorization"][*] wildcard "Bearer *")"#,
            expect![[r#"
                Found uppercase characters in header name `Authorization` (header_case)
                The map key `Authorization` used to index `http.request.headers` contains uppercase characters; keys should be lowercase (e.g., "content-type")."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"any(http.response.headers["Authorization"][*] wildcard "Bearer *")"#,
            expect![[r#"
                Found uppercase characters in header name `Authorization` (header_case)
                The map key `Authorization` used to index `http.response.headers` contains uppercase characters; keys should be lowercase (e.g., "content-type")."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"any(raw.http.response.headers["Authorization"][*] wildcard "Bearer *")"#,
            expect![[r#"
                Found uppercase characters in header name `Authorization` (header_case)
                The map key `Authorization` used to index `raw.http.response.headers` contains uppercase characters; keys should be lowercase (e.g., "content-type")."#]],
        );
    }

    #[test]
    fn test_header_name_uppercase_warns() {
        expect_lint_message(
            &LINTER,
            r#"any(http.request.headers.names[*] eq "Authorization")"#,
            expect![[r#"
                Found uppercase characters in header name `Authorization` (header_case)
                Header names must always be all lowercase but `Authorization` contains uppercase characters. It should be lowercase (e.g., "content-type")."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"any(http.response.headers.names[*] eq "Authorization")"#,
            expect![[r#"
                Found uppercase characters in header name `Authorization` (header_case)
                Header names must always be all lowercase but `Authorization` contains uppercase characters. It should be lowercase (e.g., "content-type")."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"any(raw.http.response.headers.names[*] eq "Authorization")"#,
            expect![[r#"
                Found uppercase characters in header name `Authorization` (header_case)
                Header names must always be all lowercase but `Authorization` contains uppercase characters. It should be lowercase (e.g., "content-type")."#]],
        );
    }

    #[test]
    fn test_header_name_uppercase_ok() {
        assert_no_lint_message(
            &LINTER,
            r#"any(http.request.headers.names[*] eq "content-type")"#,
        );
        assert_no_lint_message(
            &LINTER,
            r#"any(http.response.headers.names[*] eq "content-type")"#,
        );
        assert_no_lint_message(
            &LINTER,
            r#"any(raw.http.response.headers.names[*] eq "content-type")"#,
        );
    }

    #[test]
    fn test_header_in_function_call() {
        expect_lint_message(
            &LINTER,
            r#"lower(http.request.headers["Mac"][0]) eq """#,
            expect![[r#"
                Found uppercase characters in header name `Mac` (header_case)
                The map key `Mac` used to index `http.request.headers` contains uppercase characters; keys should be lowercase (e.g., "content-type")."#]],
        );
    }

    #[test]
    fn test_header_in_function_call_complex() {
        expect_lint_message(
            &LINTER,
            r#"is_timed_hmac_valid_v0(
  "mysecretkey",
  concat(
    http.request.uri,
    http.request.headers["Timestamp"][0],
    "-",
    http.request.headers["Mac"][0]),
  100000,
  http.request.timestamp.sec,
  0
)"#,
            expect![[r#"
                Found uppercase characters in header name `Timestamp` (header_case)
                The map key `Timestamp` used to index `http.request.headers` contains uppercase characters; keys should be lowercase (e.g., "content-type").

                Found uppercase characters in header name `Mac` (header_case)
                The map key `Mac` used to index `http.request.headers` contains uppercase characters; keys should be lowercase (e.g., "content-type")."#]],
        );
    }
}
