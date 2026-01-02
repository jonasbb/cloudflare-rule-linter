use crate::linter::Category;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinterConfig {
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintConfig {
    pub enable_lints: Vec<Box<str>>,
    pub disable_lints: Vec<Box<str>>,
    pub enable_categories: Vec<Category>,
    pub disable_categories: Vec<Category>,
}

impl Default for LinterConfig {
    fn default() -> Self {
        Self {
            lints: LintConfig {
                enable_lints: Vec::new(),
                disable_lints: Vec::new(),
                enable_categories: Vec::new(),
                disable_categories: Vec::new(),
            },
            settings: LintSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintSettings {
    pub timestamp_bounds_min_timestamp: i64,
    pub timestamp_bounds_future_delta: i64,
}

impl Default for LintSettings {
    fn default() -> Self {
        Self {
            // January 2010
            timestamp_bounds_min_timestamp: 1262300400,
            // Roughly 5 years into the future
            timestamp_bounds_future_delta: 5 * 366 * 24 * 60 * 60,
        }
    }
}
