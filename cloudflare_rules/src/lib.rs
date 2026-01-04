//! Linter for [`wirefilter`] expressions

pub use self::linter::{LintReport, Span};
pub use crate::ast_printer::AstPrintVisitor;
pub use crate::config::{LintConfig, LintSettings, LinterConfig};
#[cfg(feature = "python")]
use pyo3::prelude::*;
use std::sync::LazyLock;
use wirefilter::Scheme;

mod ast_printer;
mod config;
mod linter;
mod scheme;

/// Default scheme matching the one Cloudflare uses
///
/// This includes fields, functions, and lists.
pub static RULE_SCHEME: LazyLock<Scheme> = LazyLock::new(scheme::build_scheme);

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
    let linter = linter::Linter::with_config(config);
    // The byte offsets will be unusable if there are multiple lines.
    // To avoid this situation, replace all newlines with spaces
    let expr = expr.replace("\n", " ");
    // The string will be trimmed from whitespace.
    // This messes with the reverse span information, as they are relative to the trimmed string.
    // For restoring them, keep track of the trailing spaces
    let trailing_whitespace = expr.chars().rev().take_while(|c| c.is_whitespace()).count();
    let mut ast = match RULE_SCHEME.parse(&expr) {
        Ok(ast) => ast,
        Err(err) => {
            return vec![LintReport {
                id: "parse_error".into(),
                url: None,
                title: "Failed to parse rule expression.".into(),
                message: err.kind.to_string(),
                span: Span::Byte(err.span_start..(err.span_start + err.span_len)),
            }];
        }
    };
    let mut result = linter.lint(&mut ast);
    // Fixup the reverse byte spans
    for lint in &mut result {
        if let Span::ReverseByte(range) = &mut lint.span {
            range.start += trailing_whitespace;
            range.end += trailing_whitespace;
        }
    }
    result
}
