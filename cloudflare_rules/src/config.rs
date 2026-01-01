use crate::linter::Category;
use serde::{Deserialize, Serialize};
use strum::VariantArray as _;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinterConfig {
    pub lints: LintConfig,
}

impl LinterConfig {
    /// Create a configuration with all lints disabled
    pub(crate) fn default_disable_all_lints() -> Self {
        Self {
            lints: LintConfig {
                enable_lints: Vec::new(),
                disable_lints: Vec::new(),
                enable_categories: Vec::new(),
                disable_categories: Vec::from(Category::VARIANTS),
            },
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
        }
    }
}
