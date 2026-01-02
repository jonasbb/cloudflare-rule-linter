use super::*;
use std::time::{SystemTime, UNIX_EPOCH};
use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, IdentifierExpr, LogicalExpr, RhsValue, RhsValues, Visitor,
};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct TimestampComparisons;

impl Lint for TimestampComparisons {
    fn name(&self) -> &'static str {
        "timestamp_comparisons"
    }

    fn category(&self) -> Category {
        Category::Correctness
    }

    fn lint(&self, config: &LinterConfig, ast: &FilterAst) -> String {
        struct TimestampVisitor {
            result: String,
            min_time: i64,
            max_time: i64,
        }

        impl Visitor<'_> for TimestampVisitor {
            fn visit_logical_expr(&mut self, node: &'_ LogicalExpr) {
                if let LogicalExpr::Comparison(comp @ ComparisonExpr { .. }) = node {
                    // Only proceed if the left-hand-side is the http.request.timestamp.sec field
                    if let IdentifierExpr::Field(field) = &comp.lhs_expr().identifier
                        && field.name() == "http.request.timestamp.sec"
                    {
                        // Get basically the right-hand side values depending on the op variant
                        match comp.operator() {
                            ComparisonOpExpr::Ordering {
                                rhs: RhsValue::Int(val),
                                ..
                            } => {
                                if *val < self.min_time {
                                    self.result += &format!(
                                        "Found comparison against http.request.timestamp.sec with \
                                         value {val} which is below min_timestamp ({}).\n",
                                        self.min_time
                                    );
                                }
                                if *val > self.max_time {
                                    // TODO: Adding max time here breaks the simple expect tests, as the value is dynamic
                                    self.result += &format!(
                                        "Found comparison against http.request.timestamp.sec with \
                                         value {val} which is too far in the future.\n",
                                    );
                                }
                            }
                            ComparisonOpExpr::OneOf(RhsValues::Int(vs)) => {
                                for v in vs {
                                    // v is an IntRange
                                    let range: std::ops::RangeInclusive<i64> = v.clone().into();
                                    let low = *range.start();
                                    let high = *range.end();

                                    if low < self.min_time {
                                        self.result += &format!(
                                            "Found comparison against http.request.timestamp.sec \
                                             with value {low} which is below min_timestamp ({}).\n",
                                            self.min_time
                                        );
                                    }
                                    if high > self.max_time {
                                        // TODO: Adding max time here breaks the simple expect tests, as the value is dynamic
                                        self.result += &format!(
                                            "Found comparison against http.request.timestamp.sec \
                                             with value {high} which is too far in the future.\n"
                                        );
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }

                self.visit_expr(node);
            }
        }

        let now_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut visitor = TimestampVisitor {
            result: String::new(),
            min_time: config.settings.timestamp_bounds_min_timestamp,
            max_time: now_timestamp + config.settings.timestamp_bounds_future_delta,
        };

        ast.walk(&mut visitor);
        visitor.result
    }
}

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    static LINTER: LazyLock<Linter> = LazyLock::new(|| {
        let mut linter = Linter::new();
        linter.config = LinterConfig::default_disable_all_lints();
        linter.config.lints.enable_lints = vec![TimestampComparisons.name().into()];
        linter
    });

    #[test]
    fn test_min_timestamp_violation() {
        expect_lint_message(
            &LINTER,
            "http.request.timestamp.sec eq 1104534000",
            expect![[r#"
                Found comparison against http.request.timestamp.sec with value 1104534000 which is below min_timestamp (1262300400).
            "#]],
        );
    }

    #[test]
    fn test_min_timestamp_ok() {
        assert_no_lint_message(&LINTER, "http.request.timestamp.sec eq 1577833200");
    }

    #[test]
    fn test_future_too_far() {
        // Test year 3000
        expect_lint_message(
            &LINTER,
            "http.request.timestamp.sec eq 32503676400",
            expect![[r#"
                Found comparison against http.request.timestamp.sec with value 32503676400 which is too far in the future.
            "#]],
        );
    }

    #[test]
    fn test_future_ok() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ok_val = now + 86400;
        let expr = format!("http.request.timestamp.sec eq {ok_val}");
        assert_no_lint_message(&LINTER, &expr);
    }

    #[test]
    fn test_one_of_checks() {
        expect_lint_message(
            &LINTER,
            "http.request.timestamp.sec in {1104500000..1577833299}",
            expect![[r#"
                Found comparison against http.request.timestamp.sec with value 1104500000 which is below min_timestamp (1262300400).
            "#]],
        );
    }
}
