use crate::config::LinterConfig;
use serde::{Deserialize, Serialize};
use std::iter;
use std::ops::Range;
use wirefilter::FilterAst;

mod deprecated_field;
mod duplicate_list_entries;
mod illogical_condition;
mod negated_comparison;
mod regex_raw_strings;
mod reserved_ip_space;
mod timestamp_bounds;

pub static LINT_REGISTRY: &[&'static (dyn Lint + Send + Sync + 'static)] = &[
    &reserved_ip_space::ReservedIpSpace,
    &negated_comparison::NegatedComparison,
    &illogical_condition::IllogicalCondition,
    &duplicate_list_entries::DuplicateListEntries,
    &regex_raw_strings::RegexRawStrings,
    &deprecated_field::DeprecatedField,
    &timestamp_bounds::TimestampComparisons,
];

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, strum::VariantArray)]
pub enum Category {
    Correctness,
    Deprecated,
    Style,
}

pub trait Lint {
    fn name(&self) -> &'static str;
    fn category(&self) -> Category;

    fn lint(&self, config: &LinterConfig, ast: &FilterAst) -> Vec<LintReport>;
}

#[cfg_attr(feature = "python", ::pyo3::pyclass)]
#[derive(Debug, Clone)]
pub struct LintReport {
    pub id: String,
    pub url: Option<String>,
    pub title: String,
    pub message: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Span {
    Missing,
    Byte(Range<usize>),
    ReverseByte(Range<usize>),
}

impl std::fmt::Display for LintReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})\n{}", self.title, self.id, self.message)
    }
}

pub struct Linter {
    config: LinterConfig,
}

impl Linter {
    pub fn new() -> Self {
        Self {
            config: LinterConfig::default(),
        }
    }

    pub fn lint(&self, ast: &mut FilterAst) -> Vec<LintReport> {
        let mut results = Vec::new();

        // Check for all lints that should run
        let mut runlint = vec![true; LINT_REGISTRY.len()];
        for (rl, lint) in iter::zip(&mut runlint, LINT_REGISTRY) {
            if self
                .config
                .lints
                .enable_categories
                .contains(&lint.category())
            {
                *rl = true;
            }
            if self
                .config
                .lints
                .disable_categories
                .contains(&lint.category())
            {
                *rl = false;
            }
            for enable_lint in &self.config.lints.enable_lints {
                if &**enable_lint == lint.name() {
                    *rl = true;
                }
            }
            for disable_lint in &self.config.lints.disable_lints {
                if &**disable_lint == lint.name() {
                    *rl = false;
                }
            }
        }

        // Run all enabled lints
        self.simplify_ast(ast);
        for (rl, lint) in iter::zip(runlint, LINT_REGISTRY) {
            if rl {
                results.extend(lint.lint(&self.config, ast));
            }
        }
        results
    }

    fn simplify_ast(&self, ast: &mut FilterAst) {
        // Parens in the AST are no longer semantically relevant, so we can remove them
        // This will make further analysis easier, as we don't have to consider parens nodes
        //
        // This might reveal further simplification opportunities of combining expressions
        // (e.g., A and (B and C) => A and B and C)

        struct SimplifyVisitor;
        impl wirefilter::VisitorMut<'_> for SimplifyVisitor {
            fn visit_logical_expr(&mut self, node: &'_ mut wirefilter::LogicalExpr) {
                match node {
                    wirefilter::LogicalExpr::Combining { op, items, .. } => {
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
                                reverse_span,
                            } = item
                            {
                                if inner_op == *op {
                                    // Flatten the inner items
                                    new_items.extend(inner_items);
                                } else {
                                    new_items.push(wirefilter::LogicalExpr::Combining {
                                        op: inner_op,
                                        items: inner_items,
                                        reverse_span,
                                    });
                                }
                            } else {
                                new_items.push(item);
                            }
                        }
                        *items = new_items;
                    }
                    wirefilter::LogicalExpr::Parenthesized(parenthesized_expr) => {
                        self.visit_logical_expr(&mut parenthesized_expr.expr);
                        // Replace the parenthesized expression with its inner expression
                        *node = parenthesized_expr.expr.clone();
                    }
                    wirefilter::LogicalExpr::Unary { arg, .. } => {
                        self.visit_logical_expr(arg);
                    }
                    wirefilter::LogicalExpr::Comparison(comparison_expr) => {
                        self.visit_comparison_expr(comparison_expr);
                    }
                }
            }
        }

        let mut visitor = SimplifyVisitor;
        ast.walk_mut(&mut visitor);
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::RULE_SCHEME;
    pub(super) use expect_test::{Expect, expect};
    pub(super) use std::sync::LazyLock;

    #[track_caller]
    pub(super) fn expect_lint_message(linter: &Linter, expr: &str, expected: Expect) {
        let mut ast = RULE_SCHEME
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        let reports = linter.lint(&mut ast);
        assert!(
            !reports.is_empty(),
            "Expected a lint message but received nothing."
        );
        let mut combined_report = String::new();
        for m in reports {
            if !combined_report.is_empty() {
                combined_report.push_str("\n\n");
            }
            combined_report.push_str(&m.to_string());
        }
        expected.assert_eq(&combined_report);
    }

    #[track_caller]
    pub(super) fn assert_no_lint_message(linter: &Linter, expr: &str) {
        let mut ast = RULE_SCHEME
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        let reports = linter.lint(&mut ast);
        let mut combined_report = String::new();
        for m in &reports {
            if !combined_report.is_empty() {
                combined_report.push_str("\n\n");
            }
            combined_report.push_str(&m.to_string());
        }
        assert!(
            reports.is_empty(),
            "Expected no lint message but received:\n{}",
            combined_report
        );
    }

    #[track_caller]
    pub(super) fn assert_simplify_ast(linter: &Linter, expr: &str, expected: Expect) {
        let mut ast = RULE_SCHEME
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        linter.simplify_ast(&mut ast);
        expected.assert_debug_eq(&ast);
    }

    static LINTER: LazyLock<Linter> = LazyLock::new(|| {
        let mut linter = Linter::new();
        linter.config = LinterConfig::default_disable_all_lints();
        linter
    });

    #[test]
    fn test_simplify_parens() {
        assert_simplify_ast(
            &LINTER,
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
    fn test_simplify_not_parens() {
        assert_simplify_ast(
            &LINTER,
            "not (ssl)",
            expect![[r#"
                Unary {
                    op: Not,
                    arg: Comparison(
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
                }
            "#]],
        );
        assert_simplify_ast(
            &LINTER,
            "not ( ( ( not ( ( ssl ) ) ) ) )",
            expect![[r#"
                Unary {
                    op: Not,
                    arg: Unary {
                        op: Not,
                        arg: Comparison(
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
                    },
                }
            "#]],
        );
    }

    #[test]
    fn test_simplify_parens_levels() {
        assert_simplify_ast(
            &LINTER,
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
}
