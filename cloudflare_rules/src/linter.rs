use crate::config::LinterConfig;
use serde::{Deserialize, Serialize};
use std::iter;
use wirefilter::FilterAst;

mod duplicate_list_entries;
mod illogical_condition;
mod negated_comparison;
mod reserved_ip_space;
mod regex_raw_strings;
mod deprecated_field;

pub static LINT_REGISTRY: &[&'static (dyn Lint + Send + Sync + 'static)] = &[
    &reserved_ip_space::ReservedIpSpace,
    &negated_comparison::NegatedComparison,
    &illogical_condition::IllogicalCondition,
    &duplicate_list_entries::DuplicateListEntries,
    &regex_raw_strings::RegexRawStrings,
    &deprecated_field::DeprecatedField,
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

    fn lint(&self, ast: &FilterAst) -> String;
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

    pub fn lint(&self, ast: &mut FilterAst) -> String {
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

        let mut res = String::new();
        // Run all enabled lints
        self.simplify_ast(ast);
        for (rl, lint) in iter::zip(runlint, LINT_REGISTRY) {
            if rl {
                res += &lint.lint(ast);
            }
        }
        res
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
        let msg = linter.lint(&mut ast);
        assert!(
            !msg.is_empty(),
            "Expected a lint message but received nothing."
        );
        expected.assert_eq(&msg);
    }

    #[track_caller]
    pub(super) fn assert_no_lint_message(linter: &Linter, expr: &str) {
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
