use crate::linter::Category;
use serde::{Deserialize, Serialize};
use std::str::FromStr as _;

/// Configuration for a Linter
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LinterConfig {
    /// Configuration about enabled lints and categories
    pub lints: LintConfig,
    /// Minimum allowed timestamp to use in comparisons against
    /// `http.request.timestamp.sec`.
    pub settings: LintSettings,
}

impl LinterConfig {
    /// Create a configuration with all lints disabled
    #[cfg(test)]
    pub(crate) fn default_disable_all_lints() -> Self {
        use strum::VariantArray as _;
        Self {
            lints: LintConfig {
                enable_lints: Vec::new(),
                disable_lints: Vec::new(),
                enable_categories: Vec::new(),
                disable_categories: Vec::from(Category::VARIANTS),
            },
            settings: LintSettings::default(),
        }
    }

    /// Parse a string of +Category,-Category,+Lint,-Lint
    pub fn parse_expr_config(&mut self, expr_cfg: &str) -> Result<(), String> {
        for cmd in expr_cfg.split(",") {
            let cmd = cmd.trim();
            let action = cmd.chars().next();
            match action {
                Some('+') => {
                    let cmd_value = &cmd[1..];
                    // Try parsing category
                    if let Ok(cat) = Category::from_str(cmd_value) {
                        self.lints.enable_categories.push(cat);
                    } else {
                        self.lints.enable_lints.push(cmd_value.into());
                    }
                }
                Some('-') => {
                    let cmd_value = &cmd[1..];
                    // Try parsing category
                    if let Ok(cat) = Category::from_str(cmd_value) {
                        self.lints.disable_categories.push(cat);
                    } else {
                        self.lints.disable_lints.push(cmd_value.into());
                    }}
                None => return Err("Unknown action symbol, expected + or - but got empty string".to_string()),
                Some(c) => return Err(format!("Unknown action symbol, expected + or - but `{c}`")),
            }
        }
        Ok(())
    }
}

/// Configuration about enabled lints and categories
///
/// The values are read in this order:
/// 1. `enable_categories`
/// 2. `disable_categories`
/// 3. `enable_lints`
/// 4. `disable_lints`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LintConfig {
    /// Enable lints by lint ID
    pub enable_lints: Vec<Box<str>>,
    /// Disable lints by lint ID
    pub disable_lints: Vec<Box<str>>,
    /// Enable all lints in a category
    pub enable_categories: Vec<Category>,
    /// Disable all lints in a category
    pub disable_categories: Vec<Category>,
}

/// Configurations for individual lints
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LintSettings {
    /// Default value: January 2010
    pub timestamp_bounds_min_timestamp: i64,
    /// Default value: Roughly 5 years into the future
    pub timestamp_bounds_future_delta: i64,
}

impl Default for LintSettings {
    fn default() -> Self {
        Self {
            // Default value: January 2010
            timestamp_bounds_min_timestamp: 1262300400,
            // Default value: Roughly 5 years into the future
            timestamp_bounds_future_delta: 5 * 366 * 24 * 60 * 60,
        }
    }
}
