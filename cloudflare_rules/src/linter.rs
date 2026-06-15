use crate::config::LinterConfig;
use crate::phase::Phase;
use serde::{Deserialize, Serialize};
use std::iter;
use std::ops::Range;
use wirefilter::{FilterAst, FilterValueAst};

mod deprecated_field;
mod duplicate_list_entries;
mod empty_list;
mod header_case;
mod illogical_condition;
mod invalid_list_name;
mod negated_comparison;
mod operator_style;
mod overly_permissive_pattern;
mod regex_raw_strings;
mod replace_functions_limit;
mod reserved_ip_space;
mod suspicious_regex;
mod timestamp_bounds;
mod unnecessary_patterns;
mod value_domain;

pub struct Lint {
    /// Identifiable name of the lint rule, should be unique across all rules
    pub name: &'static str,
    /// Short single line description of the lint rule
    pub description: &'static str,
    pub category: Category,
    pub lint_fn: fn(&LinterConfig, &FilterAst, &str) -> Vec<LintReport>,
    pub lint_value_fn: fn(&LinterConfig, &FilterValueAst, &str) -> Vec<LintReport>,
}

inventory::collect!(Lint);

/// Generate a URL for the given lint rule name, pointing to the documentation for that rule
fn create_url(name: &str) -> String {
    format!(
        "https://github.com/jonasbb/cloudflare-rule-linter/blob/master/docs/{}.md",
        name
    )
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    strum::VariantArray,
    strum::EnumString,
    strum::Display,
)]
#[strum(serialize_all = "lowercase")]
pub enum Category {
    Correctness,
    Deprecated,
    Suspicious,
    Style,
}

/// List report for some finding with the rule expression
#[cfg_attr(feature = "python", ::pyo3::pyclass(from_py_object))]
#[derive(Debug, Clone)]
pub struct LintReport {
    /// Identifiable ID of the lint rule
    pub id: String,
    /// URL that explains the ID in more detail
    pub url: Option<String>,
    /// Message title
    pub title: String,
    /// More detailed message describing the issue and potential fixes
    pub message: String,
    /// Location of the problematic rule
    pub span: Span,
}

/// Span indicating a location inside a rule expression string
#[derive(Debug, Clone)]
pub enum Span {
    /// No span information available
    Missing,
    /// Count bytes from the start of the rule expression
    Byte(Range<usize>),
    /// Count bytes from the end of the rule expression
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
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            config: LinterConfig::default(),
        }
    }

    pub fn with_config(config: LinterConfig) -> Self {
        Self { config }
    }

    #[allow(dead_code)]
    pub fn lint(&self, ast: &mut FilterAst, expr: &str) -> Vec<LintReport> {
        self.lint_with_phase(ast, expr, Phase::Maximum)
    }

    /// Lint the provided AST using an explicit `rule_phase` for this invocation.
    pub fn lint_with_phase(
        &self,
        ast: &mut FilterAst,
        expr: &str,
        _rule_phase: Phase,
    ) -> Vec<LintReport> {
        // Simplify the AST before running any lints, so that all lints can operate on a normalized AST structure
        ast.walk_mut(&mut SimplifyVisitor);

        let mut results = Vec::new();
        // Run all enabled lints
        for lint in self.iter_active_lints() {
            results.extend((lint.lint_fn)(&self.config, ast, expr));
        }
        results
    }

    #[allow(dead_code)]
    pub fn lint_value(&self, ast: &mut FilterValueAst, expr: &str) -> Vec<LintReport> {
        self.lint_value_with_phase(ast, expr, Phase::Maximum)
    }

    /// Lint the provided AST using an explicit `rule_phase` for this invocation.
    pub fn lint_value_with_phase(
        &self,
        ast: &mut FilterValueAst,
        expr: &str,
        _rule_phase: Phase,
    ) -> Vec<LintReport> {
        // Simplify the AST before running any lints, so that all lints can operate on a normalized AST structure
        ast.walk_mut(&mut SimplifyVisitor);

        let mut results = Vec::new();
        // Run all enabled lints
        for lint in self.iter_active_lints() {
            results.extend((lint.lint_value_fn)(&self.config, ast, expr));
        }
        results
    }

    fn iter_active_lints(&self) -> impl Iterator<Item = &Lint> {
        // Check for all lints that should run
        let mut runlint = vec![true; inventory::iter::<Lint>.into_iter().count()];
        for (rl, lint) in iter::zip(&mut runlint, inventory::iter::<Lint>) {
            if self.config.lints.enable_categories.contains(&lint.category) {
                *rl = true;
            }
            if self
                .config
                .lints
                .disable_categories
                .contains(&lint.category)
            {
                *rl = false;
            }
            for enable_lint in &self.config.lints.enable_lints {
                if &**enable_lint == lint.name {
                    *rl = true;
                }
            }
            for disable_lint in &self.config.lints.disable_lints {
                if &**disable_lint == lint.name {
                    *rl = false;
                }
            }
        }

        iter::zip(runlint, inventory::iter::<Lint>).filter_map(|(rl, lint)| rl.then_some(lint))
    }
}

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

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::SCHEMES;
    pub(super) use expect_test::{Expect, expect};
    pub(super) use std::sync::LazyLock;

    #[track_caller]
    pub(super) fn expect_lint_message(linter: &Linter, expr: &str, expected: Expect) {
        expect_lint_message_phase(linter, Phase::Maximum, expr, expected);
    }

    #[track_caller]
    pub(super) fn expect_lint_message_phase(
        linter: &Linter,
        phase: Phase,
        expr: &str,
        expected: Expect,
    ) {
        let mut ast = SCHEMES
            .get(&phase)
            .expect("SCHEMES is always set")
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        let reports = linter.lint(&mut ast, expr.trim());
        check_expect_message(&reports, &expected);
    }

    #[track_caller]
    pub(super) fn expect_value_lint_message(linter: &Linter, expr: &str, expected: Expect) {
        expect_value_lint_message_phase(linter, Phase::Maximum, expr, expected);
    }

    #[track_caller]
    pub(super) fn expect_value_lint_message_phase(
        linter: &Linter,
        phase: Phase,
        expr: &str,
        expected: Expect,
    ) {
        let mut ast = SCHEMES
            .get(&phase)
            .expect("SCHEMES is always set")
            .parse_value(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        let reports = linter.lint_value(&mut ast, expr.trim());
        check_expect_message(&reports, &expected);
    }

    #[track_caller]
    fn check_expect_message(reports: &[LintReport], expected: &Expect) {
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
        assert_no_lint_message_phase(linter, Phase::Maximum, expr);
    }

    #[track_caller]
    pub(super) fn assert_no_lint_message_phase(linter: &Linter, phase: Phase, expr: &str) {
        let mut ast = SCHEMES
            .get(&phase)
            .expect("SCHEMES is always set")
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        let reports = linter.lint(&mut ast, expr.trim());
        check_no_message(&reports);
    }

    #[track_caller]
    pub(super) fn assert_value_no_lint_message(linter: &Linter, expr: &str) {
        assert_value_no_lint_message_phase(linter, Phase::Maximum, expr);
    }

    #[track_caller]
    pub(super) fn assert_value_no_lint_message_phase(linter: &Linter, phase: Phase, expr: &str) {
        let mut ast = SCHEMES
            .get(&phase)
            .expect("SCHEMES is always set")
            .parse_value(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        let reports = linter.lint_value(&mut ast, expr.trim());
        check_no_message(&reports);
    }

    #[track_caller]
    fn check_no_message(reports: &[LintReport]) {
        let mut combined_report = String::new();
        for m in reports {
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
    pub(super) fn assert_simplify_ast(expr: &str, expected: Expect) {
        assert_simplify_ast_phase(Phase::Maximum, expr, expected);
    }

    #[track_caller]
    pub(super) fn assert_simplify_ast_phase(phase: Phase, expr: &str, expected: Expect) {
        let mut ast = SCHEMES
            .get(&phase)
            .expect("SCHEMES is always set")
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        // Simplify the AST before running any lints, so that all lints can operate on a normalized AST structure
        ast.walk_mut(&mut SimplifyVisitor);
        expected.assert_debug_eq(&ast);
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
                                    reverse_span: 13..10,
                                },
                                op: IsTrue,
                                reverse_span: 13..10,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                    reverse_span: 4..1,
                                },
                                op: IsTrue,
                                reverse_span: 4..1,
                            },
                        ),
                    ],
                    reverse_span: 13..1,
                }
            "#]],
        );
    }

    #[test]
    fn test_simplify_not_parens() {
        assert_simplify_ast(
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
                                reverse_span: 4..1,
                            },
                            op: IsTrue,
                            reverse_span: 4..1,
                        },
                    ),
                    reverse_span: 9..0,
                }
            "#]],
        );
        assert_simplify_ast(
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
                                    reverse_span: 13..10,
                                },
                                op: IsTrue,
                                reverse_span: 13..10,
                            },
                        ),
                        reverse_span: 21..6,
                    },
                    reverse_span: 31..0,
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
                                    reverse_span: 55..52,
                                },
                                op: IsTrue,
                                reverse_span: 55..52,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                    reverse_span: 46..43,
                                },
                                op: IsTrue,
                                reverse_span: 46..43,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                    reverse_span: 38..35,
                                },
                                op: IsTrue,
                                reverse_span: 38..35,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                    reverse_span: 29..26,
                                },
                                op: IsTrue,
                                reverse_span: 29..26,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                    reverse_span: 21..18,
                                },
                                op: IsTrue,
                                reverse_span: 21..18,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                    reverse_span: 13..10,
                                },
                                op: IsTrue,
                                reverse_span: 13..10,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                    reverse_span: 5..2,
                                },
                                op: IsTrue,
                                reverse_span: 5..2,
                            },
                        ),
                    ],
                    reverse_span: 55..2,
                }
            "#]],
        );
    }
}
