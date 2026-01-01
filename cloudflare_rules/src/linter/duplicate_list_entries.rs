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

    fn lint(&self, ast: &FilterAst) -> String {
        // Check for duplicate entries in list comparisons
        // A in {1 2 2} => duplicate entry 2

        struct DuplicateListEntriesVisitor {
            result: String,
        }
        let mut visitor = DuplicateListEntriesVisitor {
            result: String::new(),
        };

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

                                        self.result += &format!(
                                            "Found duplicate entry in list comparison: \
                                             {node_str}\nThe values `{}..{}` and `{}..{}` \
                                             overlap.\n",
                                            range_i.start(),
                                            range_i.end(),
                                            range_j.start(),
                                            range_j.end(),
                                        );
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

                                        self.result += &format!(
                                            "Found duplicate entry in list comparison: \
                                             {node_str}\nThe values `{range_i_str}` and \
                                             `{range_j_str}` overlap.\n",
                                        );
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

                                        self.result += &format!(
                                            "Found duplicate entry in list comparison: \
                                             {node_str}\nThe value `{item_str}` appears multiple \
                                             times in the list.\n"
                                        );
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
                Found duplicate entry in list comparison: ip.src in {1.2.3.4 1.2.3.4}
                The values `1.2.3.4` and `1.2.3.4` overlap.
            "#]],
        );
        expect_lint_message(
            &LINTER,
            r#"ip.src in {1.2.3.4 1.0.0.0/8}"#,
            expect![[r#"
                Found duplicate entry in list comparison: ip.src in {1.2.3.4 1.0.0.0/8}
                The values `1.2.3.4` and `1.0.0.0/8` overlap.
            "#]],
        );
        expect_lint_message(
            &LINTER,
            r#"ip.src in {2000::/32 2000::/48}"#,
            expect![[r#"
                Found duplicate entry in list comparison: ip.src in {2000::/32 2000::/48}
                The values `2000::/32` and `2000::/48` overlap.
            "#]],
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
                Found duplicate entry in list comparison: http.host in {"example.com" "example.com"}
                The value `example.com` appears multiple times in the list.
            "#]],
        );
    }

    #[test]
    fn test_int_range_overlap() {
        expect_lint_message(
            &LINTER,
            r#"http.response.code in {400 300..499}"#,
            expect![[r#"
                Found duplicate entry in list comparison: http.response.code in {400 300..499}
                The values `400..400` and `300..499` overlap.
            "#]],
        );
        expect_lint_message(
            &LINTER,
            r#"http.response.code in {200..499 300..307}"#,
            expect![[r#"
            Found duplicate entry in list comparison: http.response.code in {200..499 300..307}
            The values `200..499` and `300..307` overlap.
        "#]],
        );

        assert_no_lint_message(
            &LINTER,
            r#"http.response.code in {200 201 202..204 205..207 208}"#,
        );
    }
}
