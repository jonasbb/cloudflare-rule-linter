use super::*;
use crate::ast_printer::AstPrintVisitor;
use std::ops::RangeInclusive;
use wirefilter::{ComparisonExpr, ComparisonOpExpr, ExplicitIpRange, RhsValues, Visitor};
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct DuplicateListEntries;
impl Lint for DuplicateListEntries {
    fn name(&self) -> &'static str {
        "duplicate_list_entries"
    }

    fn category(&self) -> Category {
        Category::Correctness
    }

    fn lint(&self, _config: &LinterConfig, ast: &FilterAst) -> Vec<LintReport> {
        // Check for duplicate entries in list comparisons
        // A in {1 2 2} => duplicate entry 2

        struct DuplicateListEntriesVisitor {
            result: Vec<LintReport>,
        }
        let mut visitor = DuplicateListEntriesVisitor { result: Vec::new() };

        impl Visitor<'_> for DuplicateListEntriesVisitor {
            fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
                if let ComparisonOpExpr::OneOf(values) = &node.op {
                    match values {
                        RhsValues::Int(int_ranges) => {
                            for idx in 0..int_ranges.len() {
                                let range_i: RangeInclusive<i64> = int_ranges[idx].clone().into();
                                for range_j in &int_ranges[idx + 1..] {
                                    let range_j: RangeInclusive<i64> = range_j.into();
                                    // Check for overlap
                                    if range_i.start() <= range_j.end()
                                        && range_j.start() <= range_i.end()
                                    {
                                        let node_str =
                                            AstPrintVisitor::comparison_expr_to_string(node);
                                        self.result.push(LintReport {
                                            id: "duplicate_list_entries".into(),
                                            url: None,
                                            title: "Found duplicate entry in list".into(),
                                            message: format!(
                                                "The values `{}..{}` and `{}..{}` overlap.",
                                                range_i.start(),
                                                range_i.end(),
                                                range_j.start(),
                                                range_j.end(),
                                            ),
                                            span_start: None,
                                            span_end: None,
                                        });
                                    }
                                }
                            }
                        }
                        RhsValues::Ip(ip_ranges) => {
                            for idx in 0..ip_ranges.len() {
                                let range_i = &ip_ranges[idx];
                                for range_j in &ip_ranges[idx + 1..] {
                                    // Check for overlap
                                    let overlaps = match (
                                        ExplicitIpRange::from(range_i.clone()),
                                        ExplicitIpRange::from(range_j.clone()),
                                    ) {
                                        (ExplicitIpRange::V4(r_i), ExplicitIpRange::V4(r_j)) => {
                                            r_i.start() <= r_j.end() && r_j.start() <= r_i.end()
                                        }
                                        (ExplicitIpRange::V6(r_i), ExplicitIpRange::V6(r_j)) => {
                                            r_i.start() <= r_j.end() && r_j.start() <= r_i.end()
                                        }
                                        // Different IP versions cannot overlap
                                        _ => false,
                                    };

                                    if overlaps {
                                        let node_str =
                                            AstPrintVisitor::comparison_expr_to_string(node);
                                        let range_i_str = AstPrintVisitor::format_ip_range(range_i);
                                        let range_j_str = AstPrintVisitor::format_ip_range(range_j);
                                        self.result.push(LintReport {
                                            id: "duplicate_list_entries".into(),
                                            url: None,
                                            title: "Found duplicate entry in list".into(),
                                            message: format!(
                                                "The values `{range_i_str}` and `{range_j_str}` \
                                                 overlap."
                                            ),
                                            span_start: None,
                                            span_end: None,
                                        });
                                    }
                                }
                            }
                        }
                        RhsValues::Bytes(items) => {
                            for idx in 0..items.len() {
                                let item_i = &items[idx].data;
                                for item_j in &items[idx + 1..] {
                                    let item_j = &item_j.data;
                                    if item_i == item_j {
                                        let node_str =
                                            AstPrintVisitor::comparison_expr_to_string(node);
                                        let item_str = AstPrintVisitor::escape_bytes(item_i);
                                        self.result.push(LintReport {
                                            id: "duplicate_list_entries".into(),
                                            url: None,
                                            title: "Found duplicate entry in list".into(),
                                            message: format!(
                                                "The value `{item_str}` appears multiple times in \
                                                 the list."
                                            ),
                                            span_start: None,
                                            span_end: None,
                                        });
                                    }
                                }
                            }
                        }
                        // Unreachable branches due to uninhabited types
                        RhsValues::Array(..) | RhsValues::Bool(..) | RhsValues::Map(..) => {
                            unreachable!()
                        }
                    }
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
        linter.config.lints.enable_lints = vec![DuplicateListEntries.name().into()];
        linter
    });

    #[test]
    fn test_ip_range_overlap() {
        expect_lint_message(
            &LINTER,
            r#"ip.src in {1.2.3.4 1.2.3.4}"#,
            expect![[r#"
                Found duplicate entry in list (duplicate_list_entries)
                The values `1.2.3.4` and `1.2.3.4` overlap."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"ip.src in {1.2.3.4 1.0.0.0/8}"#,
            expect![[r#"
                Found duplicate entry in list (duplicate_list_entries)
                The values `1.2.3.4` and `1.0.0.0/8` overlap."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"ip.src in {2000::/32 2000::/48}"#,
            expect![[r#"
                Found duplicate entry in list (duplicate_list_entries)
                The values `2000::/32` and `2000::/48` overlap."#]],
        );

        // Different IP versions do not overlap
        assert_no_lint_message(&LINTER, r#"ip.src in {1.2.3.4 2000::/16}"#);
    }

    #[test]
    fn test_bytes_overlap() {
        expect_lint_message(
            &LINTER,
            r#"http.host in {"example.com" "example.com"}"#,
            expect![[r#"
                Found duplicate entry in list (duplicate_list_entries)
                The value `example.com` appears multiple times in the list."#]],
        );
    }

    #[test]
    fn test_int_range_overlap() {
        expect_lint_message(
            &LINTER,
            r#"http.response.code in {400 300..499}"#,
            expect![[r#"
                Found duplicate entry in list (duplicate_list_entries)
                The values `400..400` and `300..499` overlap."#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.response.code in {200..499 300..307}"#,
            expect![[r#"
                Found duplicate entry in list (duplicate_list_entries)
                The values `200..499` and `300..307` overlap."#]],
        );

        assert_no_lint_message(
            &LINTER,
            r#"http.response.code in {200 201 202..204 205..207 208}"#,
        );
    }
}
