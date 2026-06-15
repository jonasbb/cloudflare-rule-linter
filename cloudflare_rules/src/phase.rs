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
    /// This is a superset of all phases, used for lints that apply to all phases.
    ///
    /// It will contain all fields and functions from all phases.
    /// Fields: <https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/>
    /// Functions: <https://developers.cloudflare.com/ruleset-engine/rules-language/functions/>
    #[default]
    #[strum(ascii_case_insensitive)]
    Maximum,
    /// API JWT Validation rules
    #[strum(ascii_case_insensitive)]
    ApiJwtValidation,
    /// Bulk Redirects filter `http_request_redirect`
    ///
    /// <https://developers.cloudflare.com/rules/url-forwarding/bulk-redirects/reference/fields-functions/>
    #[strum(ascii_case_insensitive)]
    BulkRedirectsFilter,
    /// Custom Error rules
    #[strum(ascii_case_insensitive)]
    CustomError,
    /// Custom WAF rules `http_request_firewall_custom`
    #[strum(ascii_case_insensitive)]
    CustomRules,
    /// Request Header Transform rules
    ///
    /// <https://developers.cloudflare.com/rules/transform/request-header-modification/reference/fields-functions/>
    #[strum(ascii_case_insensitive)]
    HeaderRequest,
    /// Response Header Transform rules `http_request_late_transform`
    ///
    /// <https://developers.cloudflare.com/rules/transform/response-header-modification/reference/fields-functions/>
    #[strum(ascii_case_insensitive)]
    HeaderResponse,
    /// Rate Limiting rules `http_request_ratelimit`
    #[strum(ascii_case_insensitive)]
    RateLimit,
    /// The filter expression for URL Redirect
    #[strum(ascii_case_insensitive)]
    UrlRedirectFilter,
    /// The dynamic target for URL Redirect rules
    #[strum(ascii_case_insensitive)]
    UrlRedirectTarget,
    /// The filter expression for URL Rewrite rules
    ///
    /// <https://developers.cloudflare.com/rules/transform/url-rewrite/reference/fields-functions/>
    #[strum(ascii_case_insensitive)]
    UrlRewriteFilter,
    /// The target expression for URL Rewrite rules
    ///
    /// <https://developers.cloudflare.com/rules/transform/url-rewrite/reference/fields-functions/>
    #[strum(ascii_case_insensitive)]
    UrlRewriteTarget,
}
