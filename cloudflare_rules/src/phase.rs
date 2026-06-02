use serde::{Deserialize, Serialize};

/// Phase in which a rule is evaluated. This is used by the linter
/// to gate lints and (eventually) to select a phase-specific Scheme.
#[derive(
    Default,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::EnumString,
    strum::Display,
    strum::VariantNames,
    strum::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum Phase {
    HttpRequest,
    HttpResponse,
    TransformRequest,
    TransformResponse,
    TransformRewrite,
    UrlRedirect,
    CustomWAF,
    RateLimit,
    ApiJwtValidation,
    NetworkFirewall,
    CustomError,
    #[default]
    Unknown,
}
