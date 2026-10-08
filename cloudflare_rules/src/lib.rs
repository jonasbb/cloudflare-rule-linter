//! Linter for [`wirefilter`] expressions

pub use self::linter::{LintReport, Span};
pub use crate::ast_printer::AstPrintVisitor;
pub use crate::config::{LintConfig, LintSettings, LinterConfig};
pub use crate::phase::Phase;
pub use crate::scheme::SCHEMES;
#[cfg(feature = "python")]
use pyo3::prelude::*;
use std::str::FromStr;
use strum::IntoEnumIterator;

mod ast_printer;
mod config;
mod linter;
mod phase;
mod scheme;

/// A Python module implemented in Rust.
#[cfg(feature = "python")]
#[pymodule]
mod cloudflare_rules {
    use super::*;

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    fn parse_expression(expr: &str) -> PyResult<Vec<LintReport>> {
        Ok(super::parse_and_lint_expression(expr))
    }
}

/// Take a [`wirefilter`] expression and a string and run the linter on it.
pub fn parse_and_lint_expression(expr: &str) -> Vec<LintReport> {
    let config = LinterConfig::default();
    parse_and_lint_expression_with_config(config, expr)
}

/// Take a [`wirefilter`] expression and a string and run the linter on it.
pub fn parse_and_lint_expression_with_config(config: LinterConfig, expr: &str) -> Vec<LintReport> {
    parse_and_lint_expression_with_config_and_phase(config, expr, Phase::Maximum)
}

/// Parse and lint an expression with an explicit `rule_phase` for this call.
pub fn parse_and_lint_expression_with_config_and_phase(
    config: LinterConfig,
    expr: &str,
    rule_phase: Phase,
) -> Vec<LintReport> {
    let mut result = Vec::new();

    // Check for maximum length of the expression
    let expression_length = expr.chars().count();
    check_expression_length(&mut result, expression_length);

    // The byte offsets will be unusable if there are multiple lines.
    // To avoid this situation, replace all newlines with spaces
    let expr = expr.replace("\n", " ");
    // The string will be trimmed from whitespace.
    // This messes with the reverse span information, as they are relative to the trimmed string.
    // For restoring them, keep track of the trailing spaces
    let trailing_whitespace = expr.chars().rev().take_while(|c| c.is_whitespace()).count();

    // Select a scheme based on the provided rule_phase. If no phase is set,
    // fallback to the default `RULE_SCHEME` to preserve backwards compatibility.
    let scheme = SCHEMES
        .get(&rule_phase)
        .expect("SCHEMES is always initialized for all phases.");

    let mut ast = match scheme.parse(&expr) {
        Ok(ast) => ast,
        Err(err) => {
            result.push(parse_error_to_lint_report(err));
            return result;
        }
    };
    // Construct the linter (moving the config) and run it with the trimmed
    // expression so lints can inspect the original source text.
    let linter = linter::Linter::with_config(config);
    result.extend(linter.lint_with_phase(&mut ast, expr.trim(), rule_phase));
    // Fixup the reverse byte spans
    for lint in &mut result {
        if let Span::ReverseByte(range) = &mut lint.span {
            range.start += trailing_whitespace;
            range.end += trailing_whitespace;
        }
    }
    result
}

/// Take a [`wirefilter`] value expression and a string and run the linter on it.
pub fn parse_and_lint_value_expression_with_config(
    config: LinterConfig,
    expr: &str,
) -> Vec<LintReport> {
    parse_and_lint_value_expression_with_config_and_phase(config, expr, Phase::Maximum)
}

/// Parse and lint a value expression with an explicit `rule_phase` for this call.
pub fn parse_and_lint_value_expression_with_config_and_phase(
    config: LinterConfig,
    expr: &str,
    rule_phase: Phase,
) -> Vec<LintReport> {
    let mut result = Vec::new();

    // Check for maximum length of the expression
    let expression_length = expr.chars().count();
    check_expression_length(&mut result, expression_length);

    // The byte offsets will be unusable if there are multiple lines.
    // To avoid this situation, replace all newlines with spaces
    let expr = expr.replace("\n", " ");
    // The string will be trimmed from whitespace.
    // This messes with the reverse span information, as they are relative to the trimmed string.
    // For restoring them, keep track of the trailing spaces
    let trailing_whitespace = expr.chars().rev().take_while(|c| c.is_whitespace()).count();

    // Select a scheme based on the provided rule_phase. If no phase is set,
    // fallback to the default `RULE_SCHEME` to preserve backwards compatibility.
    let scheme = SCHEMES
        .get(&rule_phase)
        .expect("SCHEMES is always initialized for all phases.");

    let mut ast = match scheme.parse_value(&expr) {
        Ok(ast) => ast,
        Err(err) => {
            result.push(parse_error_to_lint_report(err));
            return result;
        }
    };
    // Construct the linter (moving the config) and run it with the trimmed
    // expression so lints can inspect the original source text.
    let linter = linter::Linter::with_config(config);
    result.extend(linter.lint_value_with_phase(&mut ast, expr.trim(), rule_phase));
    // Fixup the reverse byte spans
    for lint in &mut result {
        if let Span::ReverseByte(range) = &mut lint.span {
            range.start += trailing_whitespace;
            range.end += trailing_whitespace;
        }
    }
    result
}

/// Provides an iterator over all available lints. This can be used to discover lints and their metadata.
pub fn lint_iter() -> impl Iterator<Item = &'static linter::Lint> {
    inventory::iter::<linter::Lint>.into_iter()
}

/// Provides an iterator over all available phases. This can be used to discover phases and their metadata.
pub fn phase_iter() -> impl Iterator<Item = Phase> {
    Phase::iter()
}

/// Convert a string into a matching [`Phase`]
pub fn phase_name_to_phase(phase_name: &str) -> Option<Phase> {
    Phase::from_str(phase_name).ok()
}

/// Check the length of the expression and add a lint report if it exceeds the maximum allowed length.
fn check_expression_length(result: &mut Vec<LintReport>, expression_length: usize) {
    const EXPRESSION_LENGTH_LIMIT: usize = 4096;
    if expression_length > EXPRESSION_LENGTH_LIMIT {
        result.push(LintReport {
            id: "expression_length_exceeded".into(),
            url: None,
            title: format!(
                "Expression length exceeds {} characters.",
                EXPRESSION_LENGTH_LIMIT
            ),
            message: format!(
                "The expression length {} exceeded the maximum allowed of {}",
                expression_length, EXPRESSION_LENGTH_LIMIT
            ),
            span: Span::Missing,
        });
    }
}

/// Converts a [`wirefilter::ParseError`] into a [`LintReport`].
fn parse_error_to_lint_report(err: wirefilter::ParseError<'_>) -> LintReport {
    LintReport {
        id: "parse_error".into(),
        url: None,
        title: "Failed to parse rule expression.".into(),
        message: err.kind.to_string(),
        span: Span::Byte(err.span_start..(err.span_start + err.span_len)),
    }
}
