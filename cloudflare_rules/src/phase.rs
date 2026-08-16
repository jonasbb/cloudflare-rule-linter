use serde::{Deserialize, Serialize};

/// Phase in which a rule is evaluated
///
/// This is used by the linter to gate lints and (eventually) to select a phase-specific Scheme.
///
/// <https://developers.cloudflare.com/ruleset-engine/reference/phases-list>
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
#[non_exhaustive]
pub enum Phase {
    /// This is a superset of all phases, used for lints that apply to all phases.
    ///
    /// It will contain all fields and functions from all phases.
    /// Fields: <https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/>
    /// Functions: <https://developers.cloudflare.com/ruleset-engine/rules-language/functions/>
    #[default]
    #[strum(ascii_case_insensitive, to_string = "Maximum", serialize = "maximum")]
    Maximum,

    /*
    HTTP Request Phases
    */
    /// Single Redirects
    ///
    /// <https://developers.cloudflare.com/rules/url-forwarding/single-redirects/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Single Redirects",
        serialize = "http_request_dynamic_redirect"
    )]
    HttpRequestDynamicRedirect,
    /// URL normalization
    ///
    /// <https://developers.cloudflare.com/rules/normalization/>
    #[strum(
        ascii_case_insensitive,
        to_string = "URL normalization",
        serialize = "http_request_sanitize"
    )]
    HttpRequestSanitize,
    /// URL Rewrite Rules
    ///
    /// <https://developers.cloudflare.com/rules/transform/url-rewrite/>
    #[strum(
        ascii_case_insensitive,
        to_string = "URL Rewrite Rules",
        serialize = "http_request_transform"
    )]
    HttpRequestTransform,
    /// API Shield (Early)
    ///
    /// <https://developers.cloudflare.com/api-shield/>
    #[strum(
        ascii_case_insensitive,
        to_string = "API Shield",
        serialize = "http_request_api_gateway_early"
    )]
    HttpRequestApiGatewayEarly,
    /// Configuration Rules
    ///
    /// <https://developers.cloudflare.com/rules/configuration-rules/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Configuration Rules",
        serialize = "http_config_settings"
    )]
    HttpConfigSettings,
    /// Origin Rules
    ///
    /// <https://developers.cloudflare.com/rules/origin-rules/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Origin Rules",
        serialize = "http_request_origin"
    )]
    HttpRequestOrigin,
    /// Custom rules (Web Application Firewall)
    ///
    /// <https://developers.cloudflare.com/waf/custom-rules/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Custom rules (Web Application Firewall)",
        serialize = "http_request_firewall_custom"
    )]
    HttpRequestFirewallCustom,
    /// Rate limiting rules (WAF)
    ///
    /// <https://developers.cloudflare.com/waf/rate-limiting-rules/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Rate limiting rules (WAF)",
        serialize = "http_ratelimit"
    )]
    HttpRatelimit,
    /// API Shield (Late)
    ///
    /// <https://developers.cloudflare.com/api-shield/>
    #[strum(
        ascii_case_insensitive,
        to_string = "API Shield",
        serialize = "http_request_api_gateway_late"
    )]
    HttpRequestApiGatewayLate,
    /// WAF Managed Rules
    ///
    /// <https://developers.cloudflare.com/waf/managed-rules/>
    #[strum(
        ascii_case_insensitive,
        to_string = "WAF Managed Rules",
        serialize = "http_request_firewall_managed"
    )]
    HttpRequestFirewallManaged,
    /// Super Bot Fight Mode
    ///
    /// <https://developers.cloudflare.com/bots/get-started/super-bot-fight-mode/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Super Bot Fight Mode",
        serialize = "http_request_sbfm"
    )]
    HttpRequestSbfm,
    /// Bulk Redirects
    ///
    /// <https://developers.cloudflare.com/rules/url-forwarding/bulk-redirects/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Bulk Redirects",
        serialize = "http_request_redirect"
    )]
    HttpRequestRedirect,
    /// Request Header Transform Rules
    ///
    /// <https://developers.cloudflare.com/rules/transform/request-header-modification/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Request Header Transform Rules",
        serialize = "http_request_late_transform"
    )]
    HttpRequestLateTransform,
    /// Cache Rules
    ///
    /// <https://developers.cloudflare.com/cache/how-to/cache-rules/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Cache Rules",
        serialize = "http_request_cache_settings"
    )]
    HttpRequestCacheSettings,
    /// Snippets
    ///
    /// <https://developers.cloudflare.com/rules/snippets/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Snippets",
        serialize = "http_request_snippets"
    )]
    HttpRequestSnippets,
    /// Cloud Connector
    ///
    /// <https://developers.cloudflare.com/rules/cloud-connector/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Cloud Connector",
        serialize = "http_request_cloud_connector"
    )]
    HttpRequestCloudConnector,

    /*
    HTTP Response Phases
    */
    /// Custom Errors
    ///
    /// <https://developers.cloudflare.com/rules/custom-errors/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Custom Errors",
        serialize = "http_custom_errors"
    )]
    HttpCustomErrors,
    /// Response Header Transform Rules
    ///
    /// <https://developers.cloudflare.com/rules/transform/response-header-modification/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Response Header Transform Rules",
        serialize = "http_response_headers_transform"
    )]
    HttpResponseHeadersTransform,
    /// Rate limiting rules (when they use response information)
    ///
    /// <https://developers.cloudflare.com/waf/rate-limiting-rules/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Rate limiting rules Counting Expression",
        serialize = "http_ratelimit_counting_expression"
    )]
    HttpRatelimitCountingExpression,
    /// Compression Rules
    ///
    /// <https://developers.cloudflare.com/rules/compression-rules/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Compression Rules",
        serialize = "http_response_compression"
    )]
    HttpResponseCompression,
    /// Cloudflare Sensitive Data Detection
    ///
    /// <https://developers.cloudflare.com/waf/managed-rules/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Cloudflare Sensitive Data Detection",
        serialize = "http_response_firewall_managed"
    )]
    HttpResponseFirewallManaged,
    /// Logpush custom fields
    ///
    /// <https://developers.cloudflare.com/logs/logpush/logpush-job/custom-fields/>
    #[strum(
        ascii_case_insensitive,
        to_string = "Logpush custom fields",
        serialize = "http_log_custom_fields"
    )]
    HttpLogCustomFields,
}
