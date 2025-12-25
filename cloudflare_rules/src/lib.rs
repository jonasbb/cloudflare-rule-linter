use self::ast_printer::AstPrintVisitor;
use anyhow::{Result, anyhow};
use pyo3::prelude::*;
use std::ops::RangeInclusive;
use std::sync::LazyLock;
use wirefilter::{ComparisonExpr, ExplicitIpRange, OrderingOp, Scheme, UnaryOp};

mod ast_printer;
mod scheme;

static RULE_SCHEME: LazyLock<Scheme> = LazyLock::new(scheme::build_scheme);

/// A Python module implemented in Rust.
#[pymodule]
mod cloudflare_rules {
    use pyo3::prelude::*;

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    fn parse_expression(expr: &str) -> PyResult<String> {
        Ok(super::parse_expression(expr)?)
    }

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    fn get_ast(expr: &str) -> PyResult<String> {
        Ok(super::get_ast(expr)?)
    }
}

pub struct Linter {}

pub enum LintCategory {
    Deprecated,
}

impl Linter {
    pub fn new() -> Self {
        Linter {}
    }

    pub fn lint(&self, ast: &mut wirefilter::FilterAst) -> String {
        let mut res = String::new();
        self.simplify_ast(ast);
        res.push_str(&self.lint_illogical_conditions(ast));
        res.push_str(&self.lint_duplicate_list_entries(ast));
        res
    }

    fn simplify_ast(&self, ast: &mut wirefilter::FilterAst) {
        // Parens in the AST are no longer semantically relevant, so we can remove them
        // This will make further analysis easier, as we don't have to consider parens nodes
        //
        // This might reveal further simplification opportunities of combining expressions
        // (e.g., A and (B and C) => A and B and C)

        struct SimplifyVisitor;
        impl wirefilter::VisitorMut<'_> for SimplifyVisitor {
            fn visit_logical_expr(&mut self, node: &'_ mut wirefilter::LogicalExpr) {
                match node {
                    wirefilter::LogicalExpr::Combining { op, items } => {
                        items.iter_mut().for_each(|item| {
                            // Recursively visit each item
                            self.visit_logical_expr(item);
                        });
                        // Check if any item is a combining expression with the same operator
                        let mut new_items = Vec::with_capacity(items.len());
                        for item in items.drain(..) {
                            if let wirefilter::LogicalExpr::Combining {
                                op: inner_op,
                                items: inner_items,
                            } = item
                            {
                                if inner_op == *op {
                                    // Flatten the inner items
                                    new_items.extend(inner_items);
                                } else {
                                    new_items.push(wirefilter::LogicalExpr::Combining {
                                        op: inner_op,
                                        items: inner_items,
                                    });
                                }
                            } else {
                                new_items.push(item);
                            }
                        }
                        *items = new_items;
                    }
                    wirefilter::LogicalExpr::Parenthesized(parenthesized_expr) => {
                        dbg!("Simplifying parenthesized expr");
                        self.visit_logical_expr(&mut parenthesized_expr.expr);
                        // Replace the parenthesized expression with its inner expression
                        *node = parenthesized_expr.expr.clone();
                    }
                    _ => {}
                }
            }
        }

        let mut visitor = SimplifyVisitor;
        ast.walk_mut(&mut visitor);
    }

    fn lint_illogical_conditions(&self, ast: &wirefilter::FilterAst) -> String {
        // Check for illogical conditions
        // A eq 1 and A eq 2 => always false
        // A ne 1 or A ne 2 => always true
        //
        // Special care for different comparisons options
        // A eq 1
        // A in {1 2}
        //
        // A ne 1
        // not A eq 1
        // not A in {1 2}
        //
        // Possible extensions for strings
        // If regex or wildcard matches do not use any placeholders, they could be considered as equal matches

        struct IllogicalConditionsVisitor {
            result: String,
        }
        let mut visitor = IllogicalConditionsVisitor {
            result: String::new(),
        };

        impl wirefilter::Visitor<'_> for IllogicalConditionsVisitor {
            fn visit_logical_expr(&mut self, node: &'_ wirefilter::LogicalExpr) {
                // Check for illogical conditions here
                if let wirefilter::LogicalExpr::Combining { op, items } = node {
                    match op {
                        wirefilter::LogicalOp::And => {
                            // Collect found index expressions to check for duplicates
                            let mut found_lhs = Vec::new();

                            // Check for always false conditions
                            for e in items {
                                // Analyze each expression
                                if let wirefilter::LogicalExpr::Comparison(ComparisonExpr {
                                    lhs,
                                    op:
                                        wirefilter::ComparisonOpExpr::Ordering {
                                            op: OrderingOp::Equal,
                                            ..
                                        }
                                        | wirefilter::ComparisonOpExpr::OneOf(..),
                                }) = e
                                {
                                    if found_lhs.contains(&lhs) {
                                        // Found duplicate equality comparison on same field
                                        // This is always false
                                        let node_str =
                                            AstPrintVisitor::logical_expr_to_string(node);
                                        let lhs_str = AstPrintVisitor::value_expr_to_string(lhs);

                                        self.result += &format!(
                                            "Found illogical condition: {node_str}\nThe value \
                                             `{lhs_str}` is compared for equality multiple times \
                                             in an AND expression.\n"
                                        );
                                    } else {
                                        found_lhs.push(lhs);
                                    }
                                }
                            }
                        }
                        wirefilter::LogicalOp::Or => {
                            // Collect found index expressions to check for duplicates
                            let mut found_lhs = Vec::new();

                            // Check for always true conditions
                            for e in items {
                                dbg!("Analyzing OR expression");
                                // Analyze each expression
                                match e {
                                    wirefilter::LogicalExpr::Comparison(ComparisonExpr {
                                        lhs,
                                        op:
                                            wirefilter::ComparisonOpExpr::Ordering {
                                                op: OrderingOp::NotEqual,
                                                ..
                                            },
                                    }) => {
                                        if found_lhs.contains(&lhs) {
                                            // Found duplicate equality comparison on same field
                                            // This is always false
                                            let node_str =
                                                AstPrintVisitor::logical_expr_to_string(node);
                                            let lhs_str =
                                                AstPrintVisitor::value_expr_to_string(lhs);

                                            self.result += &format!(
                                                "Found illogical condition: {node_str}\nThe value \
                                                 `{lhs_str}` is compared for not-equality \
                                                 multiple times in an OR expression.\n"
                                            );
                                        } else {
                                            found_lhs.push(lhs);
                                        }
                                    }
                                    wirefilter::LogicalExpr::Unary {
                                        op: UnaryOp::Not,
                                        arg,
                                    } => {
                                        if let wirefilter::LogicalExpr::Comparison(
                                            ComparisonExpr {
                                                lhs,
                                                op:
                                                    wirefilter::ComparisonOpExpr::Ordering {
                                                        op: OrderingOp::Equal,
                                                        ..
                                                    }
                                                    | wirefilter::ComparisonOpExpr::OneOf(..),
                                            },
                                        ) = &**arg
                                        {
                                            if found_lhs.contains(&lhs) {
                                                // Found duplicate equality comparison on same field
                                                // This is always false
                                                let node_str =
                                                    AstPrintVisitor::logical_expr_to_string(node);
                                                let lhs_str =
                                                    AstPrintVisitor::value_expr_to_string(lhs);

                                                self.result += &format!(
                                                    "Found illogical condition: {node_str}\nThe \
                                                     value `{lhs_str}` is compared for \
                                                     not-equality multiple times in an OR \
                                                     expression.\n"
                                                );
                                            } else {
                                                found_lhs.push(lhs);
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }

                self.visit_expr(node);
            }
        }

        ast.walk(&mut visitor);
        visitor.result
    }

    fn lint_duplicate_list_entries(&self, ast: &wirefilter::FilterAst) -> String {
        // Check for duplicate entries in list comparisons
        // A in {1 2 2} => duplicate entry 2

        struct DuplicateListEntriesVisitor {
            result: String,
        }
        let mut visitor = DuplicateListEntriesVisitor {
            result: String::new(),
        };

        impl wirefilter::Visitor<'_> for DuplicateListEntriesVisitor {
            fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
                if let wirefilter::ComparisonOpExpr::OneOf(values) = &node.op {
                    match values {
                        wirefilter::RhsValues::Int(int_ranges) => {
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
                        wirefilter::RhsValues::Ip(ip_ranges) => {
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
                        wirefilter::RhsValues::Bytes(items) => {
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
                        wirefilter::RhsValues::Array(..)
                        | wirefilter::RhsValues::Bool(..)
                        | wirefilter::RhsValues::Map(..) => unreachable!(),
                    }
                }

                self.visit_value_expr(&node.lhs);
            }
        }

        ast.walk(&mut visitor);
        visitor.result
    }
}

fn parse_expression(expr: &str) -> Result<String> {
    let linter = Linter::new();
    let mut ast = RULE_SCHEME.parse(expr).map_err(|err| anyhow!("{err}"))?;
    let result = linter.lint(&mut ast);
    Ok(result)

    // println!("Parsed filter representation: {ast:#?}",);
    // let mut visitor = ast_printer::AstPrintVisitor::new();
    // ast.walk(&mut visitor);
    // println!(
    //     "Assembled expression:\n{}\nOriginal expression:\n{}",
    //     visitor.into_string(), e
    // );

    // Ok(serde_json::to_string(&ast)?)
}

fn get_ast(expr: &str) -> Result<String> {
    let ast = RULE_SCHEME.parse(expr).map_err(|err| anyhow!("{err}"))?;
    Ok(format!("{ast:#?}"))
}

#[cfg(test)]
mod linter_tests {
    use super::*;
    use expect_test::{Expect, expect};

    #[track_caller]
    fn expect_lint_message(expr: &str, expected: Expect) {
        let linter = Linter::new();
        let mut ast = RULE_SCHEME
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        let msg = linter.lint(&mut ast);
        assert!(
            !msg.is_empty(),
            "Expected a lint message but received nothing."
        );
        expected.assert_eq(&msg);
    }

    #[track_caller]
    fn assert_no_lint_message(expr: &str) {
        let linter = Linter::new();
        let mut ast = RULE_SCHEME
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        let msg = linter.lint(&mut ast);
        assert!(
            msg.is_empty(),
            "Expected no lint message but received:\n{}",
            msg
        );
    }

    #[track_caller]
    fn assert_simplify_ast(expr: &str, expected: Expect) {
        let linter = Linter::new();
        let mut ast = RULE_SCHEME
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        linter.simplify_ast(&mut ast);
        expected.assert_debug_eq(&ast);
    }

    #[test]
    fn test_illogical_conditions_and() {
        expect_lint_message(
            r#"http.host eq "example.com" and http.host eq "example.org""#,
            expect![[r#"
                Found illogical condition: http.host eq "example.com" and http.host eq "example.org"
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
        expect_lint_message(
            r#"http.host eq "example.com" and http.host in { "example.org" }"#,
            expect![[r#"
                Found illogical condition: http.host eq "example.com" and http.host in {"example.org"}
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
        expect_lint_message(
            r#"http.host in { "example.com" } and http.host eq "example.org""#,
            expect![[r#"
                Found illogical condition: http.host in {"example.com"} and http.host eq "example.org"
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
    }

    #[test]
    fn test_illogical_conditions_and_parens() {
        expect_lint_message(
            r#"http.host eq "example.com" and (http.host eq "example.org")"#,
            expect![[r#"
                Found illogical condition: http.host eq "example.com" and http.host eq "example.org"
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
        expect_lint_message(
            r#"(http.host eq "example.com") and http.host in { "example.org" }"#,
            expect![[r#"
                Found illogical condition: http.host eq "example.com" and http.host in {"example.org"}
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
        expect_lint_message(
            r#"(http.host in { "example.com" }) and (http.host eq "example.org")"#,
            expect![[r#"
                Found illogical condition: http.host in {"example.com"} and http.host eq "example.org"
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
        expect_lint_message(
            r#"http.host eq "example.com" and (ip.src eq 1.2.3.4 and http.host eq "example.org")"#,
            expect![[r#"
                Found illogical condition: http.host eq "example.com" and ip.src eq 1.2.3.4 and http.host eq "example.org"
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
    }

    #[test]
    fn test_illogical_conditions_or() {
        expect_lint_message(
            r#"http.host != "example.com" or http.host != "example.org""#,
            expect![[r#"
                Found illogical condition: http.host ne "example.com" or http.host ne "example.org"
                The value `http.host` is compared for not-equality multiple times in an OR expression.
            "#]],
        );
        expect_lint_message(
            r#"not http.host eq "example.com" or http.host != "example.org""#,
            expect![[r#"
                Found illogical condition: not http.host eq "example.com" or http.host ne "example.org"
                The value `http.host` is compared for not-equality multiple times in an OR expression.
            "#]],
        );
        expect_lint_message(
            r#"http.host != "example.com" or not http.host eq "example.org""#,
            expect![[r#"
                Found illogical condition: http.host ne "example.com" or not http.host eq "example.org"
                The value `http.host` is compared for not-equality multiple times in an OR expression.
            "#]],
        );
        expect_lint_message(
            r#"http.host != "example.com" or not http.host in { "example.org" }"#,
            expect![[r#"
                Found illogical condition: http.host ne "example.com" or not http.host in {"example.org"}
                The value `http.host` is compared for not-equality multiple times in an OR expression.
            "#]],
        );
        expect_lint_message(
            r#"not http.host in { "example.com" } or http.host ne "example.org""#,
            expect![[r#"
                Found illogical condition: not http.host in {"example.com"} or http.host ne "example.org"
                The value `http.host` is compared for not-equality multiple times in an OR expression.
            "#]],
        );
    }

    #[test]
    fn test_simplify_parens() {
        assert_simplify_ast(
            "ssl and (ssl)",
            expect![[r#"
            Combining {
                op: And,
                items: [
                    Comparison(
                        ComparisonExpr {
                            lhs: IndexExpr {
                                identifier: Field(
                                    ssl,
                                ),
                                indexes: [],
                            },
                            op: IsTrue,
                        },
                    ),
                    Comparison(
                        ComparisonExpr {
                            lhs: IndexExpr {
                                identifier: Field(
                                    ssl,
                                ),
                                indexes: [],
                            },
                            op: IsTrue,
                        },
                    ),
                ],
            }
        "#]],
        );
    }
    #[test]
    fn test_simplify_parens_levels() {
        assert_simplify_ast(
            "ssl and (ssl and ssl and (ssl and ssl and ssl and ssl))",
            expect![[r#"
                Combining {
                    op: And,
                    items: [
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                    ],
                }
            "#]],
        );
    }

    #[test]
    fn test_ip_range_overlap() {
        expect_lint_message(
            r#"ip.src in {127.0.0.1 127.0.0.1}"#,
            expect![[r#"
            Found duplicate entry in list comparison: ip.src in {127.0.0.1 127.0.0.1}
            The values `127.0.0.1` and `127.0.0.1` overlap.
        "#]],
        );
        expect_lint_message(
            r#"ip.src in {127.0.0.1 127.0.0.0/8}"#,
            expect![[r#"
                Found duplicate entry in list comparison: ip.src in {127.0.0.1 127.0.0.0/8}
                The values `127.0.0.1` and `127.0.0.0/8` overlap.
            "#]],
        );
        expect_lint_message(
            r#"ip.src in {::/32 ::/48}"#,
            expect![[r#"
            Found duplicate entry in list comparison: ip.src in {::/32 ::/48}
            The values `::/32` and `::/48` overlap.
        "#]],
        );
        // Different IP versions do not overlap
        assert_no_lint_message(r#"ip.src in {127.0.0.1 ::/0}"#);
    }

    #[test]
    fn test_bytes_overlap() {
        expect_lint_message(
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
            r#"http.response.code in {400 300..499}"#,
            expect![[r#"
                Found duplicate entry in list comparison: http.response.code in {400 300..499}
                The values `400..400` and `300..499` overlap.
            "#]],
        );
        expect_lint_message(r#"http.response.code in {200..499 300..307}"#, expect![[r#"
            Found duplicate entry in list comparison: http.response.code in {200..499 300..307}
            The values `200..499` and `300..307` overlap.
        "#]]);

        assert_no_lint_message(r#"http.response.code in {200 201 202..204 205..207 208}"#);
    }
}
