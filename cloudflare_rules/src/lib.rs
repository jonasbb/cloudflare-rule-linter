use self::linter::LintReport;
use anyhow::{Result, anyhow};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use scheme::build_scheme;
use std::sync::LazyLock;
use wirefilter::{ParseError, Scheme};

pub mod ast_printer;
mod config;
mod linter;
mod scheme;

pub static RULE_SCHEME: LazyLock<Scheme> = LazyLock::new(scheme::build_scheme);

/// A Python module implemented in Rust.
#[cfg(feature = "python")]
#[pymodule]
mod cloudflare_rules {
    use super::*;

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    fn parse_expression(expr: &str) -> PyResult<Vec<LintReport>> {
        Ok(super::parse_expression(expr)?)
    }

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    fn get_ast(expr: &str) -> PyResult<String> {
        Ok(super::get_ast(expr)?)
    }
}

pub fn parse_expression(expr: &str) -> Result<Vec<LintReport>> {
    let linter = linter::Linter::new();
    let mut ast = match RULE_SCHEME.parse(expr) {
        Ok(ast) => ast,
        Err(err) => {
            return Ok(vec![LintReport {
                id: "parse_error".into(),
                url: None,
                title: "Failed to parse rule expression.".into(),
                message: err.kind.to_string(),
                span_start: Some(err.span_start),
                span_end: Some(err.span_start + err.span_len),
            }]);
        }
    };
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
