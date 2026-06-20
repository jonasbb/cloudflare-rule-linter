// Transform functions implementations

use crate::phase::Phase;
use std::collections::HashMap;
use std::sync::LazyLock;
use strum::IntoEnumIterator as _;
use wirefilter::{LhsValue, Scheme, Type};

#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct NumList {}

impl wirefilter::ListDefinition for NumList {
    fn new_matcher(&self) -> Box<dyn wirefilter::ListMatcher> {
        Box::new(NumList {})
    }

    fn deserialize_matcher<'de>(
        &self,
        _: Type,
        deserializer: &mut dyn erased_serde::Deserializer<'de>,
    ) -> Result<Box<dyn wirefilter::ListMatcher>, erased_serde::Error> {
        let matcher = erased_serde::deserialize::<NumList>(deserializer)?;
        Ok(Box::new(matcher))
    }
}

impl wirefilter::ListMatcher for NumList {
    fn match_value(&self, list_name: &str, val: &LhsValue<'_>) -> bool {
        match val {
            LhsValue::Int(num) => match list_name {
                "even" => num % 2 == 0,
                "odd" => num % 2 != 0,
                _ => unreachable!("Number list with unknown name: {}", list_name),
            },
            _ => unreachable!(), // TODO: is this unreachable?
        }
    }

    fn clear(&mut self) {}
}

#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpList {}

impl wirefilter::ListDefinition for IpList {
    fn new_matcher(&self) -> Box<dyn wirefilter::ListMatcher> {
        Box::new(IpList {})
    }

    fn deserialize_matcher<'de>(
        &self,
        _: Type,
        deserializer: &mut dyn erased_serde::Deserializer<'de>,
    ) -> Result<Box<dyn wirefilter::ListMatcher>, erased_serde::Error> {
        let matcher = erased_serde::deserialize::<IpList>(deserializer)?;
        Ok(Box::new(matcher))
    }
}

impl wirefilter::ListMatcher for IpList {
    fn match_value(&self, list_name: &str, val: &LhsValue<'_>) -> bool {
        match val {
            LhsValue::Ip(_) => match list_name {
                "always" => true,
                "never" => false,
                _ => unreachable!("Number list with unknown name: {}", list_name),
            },
            _ => unreachable!(), // TODO: is this unreachable?
        }
    }

    fn clear(&mut self) {}
}

/// Generate the default scheme matching the one Cloudflare uses
///
/// This includes fields, functions, and lists.
pub(crate) fn build_scheme(phase: Phase) -> Scheme {
    let mut builder = wirefilter::SchemeBuilder::new();

    // The JWT validation environment does not have any normal functions, just the special ones
    if matches!(phase, Phase::ApiJwtValidation | Phase::Maximum) {
        builder
            .add_function(
                "is_jwt_present",
                wirefilter::functions::IsJwtPresentFunction {},
            )
            .unwrap();
        builder
            .add_function("is_jwt_valid", wirefilter::functions::IsJwtValidFunction {})
            .unwrap();
    }

    // Add custom lists
    if !matches!(phase, Phase::ApiJwtValidation) {
        builder.add_list(Type::Int, NumList {}).unwrap();
        builder.add_list(Type::Ip, IpList {}).unwrap();

        // Add standard functions
        builder
            .add_function("any", wirefilter::AnyFunction {})
            .unwrap();
        builder
            .add_function("all", wirefilter::AllFunction {})
            .unwrap();
        if matches!(
            phase,
            Phase::CustomError | Phase::RateLimit | Phase::Maximum
        ) {
            builder
                .add_function("cidr", wirefilter::functions::CIDRFunction {})
                .unwrap();
            builder
                .add_function("cidr6", wirefilter::functions::CIDR6Function {})
                .unwrap();
        }
        builder
            .add_function("concat", wirefilter::ConcatFunction {})
            .unwrap();
        if matches!(
            phase,
            Phase::CustomError
                | Phase::RateLimit
                | Phase::UrlRewriteFilter
                | Phase::UrlRewriteTarget
                | Phase::HeaderRequest
                | Phase::HeaderResponse
                | Phase::Maximum
        ) {
            builder
                .add_function(
                    "decode_base64",
                    wirefilter::functions::DecodeBase64Function {},
                )
                .unwrap();
        }
        if matches!(
            phase,
            Phase::HeaderRequest | Phase::HeaderResponse | Phase::Maximum
        ) {
            builder
                .add_function(
                    "encode_base64",
                    wirefilter::functions::EncodeBase64Function {},
                )
                .unwrap();
        }
        builder
            .add_function("ends_with", wirefilter::functions::EndsWithFunction {})
            .unwrap();
        if matches!(
            phase,
            Phase::CustomError
                | Phase::UrlRewriteFilter
                | Phase::UrlRewriteTarget
                | Phase::HeaderRequest
                | Phase::HeaderResponse
                | Phase::Maximum
        ) {
            builder
                .add_function("join", wirefilter::functions::JoinFunction {})
                .unwrap();
        }
        builder
            .add_function("has_key", wirefilter::functions::HasKeyFunction {})
            .unwrap();
        builder
            .add_function("has_value", wirefilter::functions::HasValueFunction {})
            .unwrap();
        builder
            .add_function("len", wirefilter::functions::LenFunction {})
            .unwrap();
        builder
            .add_function(
                "lookup_json_integer",
                wirefilter::functions::JsonLookupIntegerFunction {},
            )
            .unwrap();
        builder
            .add_function(
                "lookup_json_string",
                wirefilter::functions::JsonLookupStringFunction {},
            )
            .unwrap();
        builder
            .add_function("lower", wirefilter::functions::LowerFunction {})
            .unwrap();
        if matches!(
            phase,
            Phase::UrlRewriteTarget | Phase::UrlRedirectFilter | Phase::Maximum
        ) {
            builder
                .add_function(
                    "regex_replace",
                    wirefilter::functions::RegexReplaceFunction {},
                )
                .unwrap();
        }
        builder
            .add_function(
                "remove_bytes",
                wirefilter::functions::RemoveBytesFunction {},
            )
            .unwrap();
        if matches!(phase, Phase::UrlRewriteTarget | Phase::Maximum) {
            builder
                .add_function(
                    "remove_query_args",
                    wirefilter::functions::RemoveQueryArgsFunction {},
                )
                .unwrap();
        }
        if matches!(phase, Phase::UrlRewriteTarget | Phase::Maximum) {
            builder
                .add_function("sha256", wirefilter::functions::Sha256Function {})
                .unwrap();
        }
        if matches!(
            phase,
            Phase::CustomError | Phase::HeaderResponse | Phase::Maximum
        ) {
            builder
                .add_function("split", wirefilter::functions::SplitFunction {})
                .unwrap();
        }
        builder
            .add_function("starts_with", wirefilter::functions::StartsWithFunction {})
            .unwrap();
        builder
            .add_function("substring", wirefilter::functions::SubstringFunction {})
            .unwrap();
        if matches!(
            phase,
            Phase::UrlRewriteTarget | Phase::UrlRedirectFilter | Phase::Maximum
        ) {
            builder
                .add_function("to_string", wirefilter::functions::ToStringFunction {})
                .unwrap();
        }
        builder
            .add_function("upper", wirefilter::functions::UpperFunction {})
            .unwrap();
        builder
            .add_function("url_decode", wirefilter::functions::UrlDecodeFunction {})
            .unwrap();
        if matches!(phase, Phase::UrlRewriteTarget | Phase::Maximum) {
            builder
                .add_function("uuidv4", wirefilter::functions::UUID4Function {})
                .unwrap();
        }
        if matches!(
            phase,
            Phase::UrlRewriteTarget | Phase::UrlRedirectFilter | Phase::Maximum
        ) {
            builder
                .add_function(
                    "wildcard_replace",
                    wirefilter::functions::WildcardReplaceFunction {},
                )
                .unwrap();
        }
        builder
            .add_function(
                "is_timed_hmac_valid_v0",
                wirefilter::functions::IsTimedHmacValidV0Function {},
            )
            .unwrap();
    }

    match phase {
        Phase::BulkRedirectsFilter => {
            add_common_fields(&mut builder, false);
            add_bulk_redirect_fields(&mut builder, false);
        }
        Phase::HeaderRequest => {
            add_common_fields(&mut builder, false);
            add_request_header_fields(&mut builder, false);
        }
        Phase::HeaderResponse => {
            add_common_fields(&mut builder, true);
            add_response_header_fields(&mut builder, true);
        }
        Phase::UrlRewriteFilter => {
            add_common_fields(&mut builder, false);
            add_url_rewrite_fields(&mut builder, false);
        }
        // TODO use better specialized fields here
        Phase::UrlRewriteTarget => {
            add_common_fields(&mut builder, false);
            add_url_rewrite_fields(&mut builder, false);
        }

        // Approximate the fields, but exclude everything that is guaranteed to be unavailable, i.e., response fields
        Phase::CustomRules => {
            add_common_fields(&mut builder, false);
            add_all_fields(&mut builder, false);
        }
        Phase::Maximum => {
            add_common_fields(&mut builder, true);
            add_all_fields(&mut builder, true);
        }

        // Request phases
        Phase::UrlRedirectFilter | Phase::UrlRedirectTarget | Phase::ApiJwtValidation => {
            add_common_fields(&mut builder, false);
        }
        // Custom errors and rate limits have access to response fields
        // https://developers.cloudflare.com/ruleset-engine/reference/phases-list/
        Phase::CustomError | Phase::RateLimit => {
            add_common_fields(&mut builder, true);
        }
    }

    // Undocumented fields
    builder
        .add_field(
            "cf.api_gateway.tokens.valid",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();

    // Fraud detection
    builder
        .add_field("cf.fraud.email_risk", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.fraud.detection_ids", Type::Array(Type::Int.into()))
        .unwrap();
    builder
        .add_field("cf.fraud.detection_tags", Type::Array(Type::Bytes.into()))
        .unwrap();
    builder.add_field("cf.fraud.attack", Type::Bytes).unwrap();

    // Sequence Rules
    // https://developers.cloudflare.com/bots/additional-configurations/sequence-rules/
    if matches!(
        phase,
        Phase::CustomRules
            | Phase::RateLimit
            | Phase::BulkRedirectsFilter
            | Phase::HeaderRequest
            | Phase::Maximum
    ) {
        builder
            .add_field("cf.sequence.current_op", Type::Bytes)
            .unwrap();
        builder
            .add_field("cf.sequence.previous_ops", Type::Array(Type::Bytes.into()))
            .unwrap();
        builder
            .add_field("cf.sequence.msec_since_op", Type::Map(Type::Int.into()))
            .unwrap();
    }

    builder.build()
}

fn add_common_fields(builder: &mut wirefilter::SchemeBuilder, #[allow(unused)] is_response: bool) {
    // GENERATED_SCHEMA_FIELDS_COMMON_START
    // Standard field definitions
    // Cf Fields
    builder.add_field("cf.edge.client_tcp", Type::Bool).unwrap();
    builder
        .add_field("cf.edge.l4.delivery_rate", Type::Int)
        .unwrap();
    builder.add_field("cf.edge.server_ip", Type::Ip).unwrap();
    builder.add_field("cf.edge.server_port", Type::Int).unwrap();
    builder
        .add_field("cf.hostname.metadata", Type::Bytes)
        .unwrap();
    builder.add_field("cf.random_seed", Type::Bytes).unwrap();
    builder.add_field("cf.ray_id", Type::Bytes).unwrap();
    builder
        .add_field("cf.timings.client_quic_rtt_msec", Type::Int)
        .unwrap();
    builder
        .add_field("cf.timings.client_tcp_rtt_msec", Type::Int)
        .unwrap();
    builder.add_field("cf.tls_cipher", Type::Bytes).unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_chain_rfc9440", Type::Bytes)
        .unwrap();
    builder
        .add_field(
            "cf.tls_client_auth.cert_chain_rfc9440_too_large",
            Type::Bool,
        )
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_fingerprint_sha1", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_fingerprint_sha256", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_issuer_dn", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_issuer_dn_legacy", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_issuer_dn_rfc2253", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_issuer_serial", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_issuer_ski", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_not_after", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_not_before", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_presented", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_revoked", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_rfc9440", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_rfc9440_too_large", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_serial", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_ski", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_subject_dn", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_subject_dn_legacy", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_subject_dn_rfc2253", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_auth.cert_verified", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.tls_client_extensions_sha1", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_extensions_sha1_le", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.tls_client_hello_length", Type::Int)
        .unwrap();
    builder
        .add_field("cf.tls_client_random", Type::Bytes)
        .unwrap();
    builder.add_field("cf.tls_version", Type::Bytes).unwrap();
    builder
        .add_field("cf.worker.upstream_zone", Type::Bytes)
        .unwrap();

    // Http Fields
    builder.add_field("http.cookie", Type::Bytes).unwrap();
    builder.add_field("http.host", Type::Bytes).unwrap();
    builder.add_field("http.referer", Type::Bytes).unwrap();
    builder
        .add_field(
            "http.request.accepted_languages",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.cookies",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field("http.request.full_uri", Type::Bytes)
        .unwrap();
    builder
        .add_field(
            "http.request.headers",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.headers.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("http.request.headers.truncated", Type::Bool)
        .unwrap();
    builder
        .add_field(
            "http.request.headers.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("http.request.method", Type::Bytes)
        .unwrap();
    builder
        .add_field("http.request.timestamp.msec", Type::Int)
        .unwrap();
    builder
        .add_field("http.request.timestamp.sec", Type::Int)
        .unwrap();
    builder.add_field("http.request.uri", Type::Bytes).unwrap();
    builder
        .add_field(
            "http.request.uri.args",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.uri.args.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.uri.args.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("http.request.uri.path", Type::Bytes)
        .unwrap();
    builder
        .add_field("http.request.uri.path.extension", Type::Bytes)
        .unwrap();
    builder
        .add_field("http.request.uri.query", Type::Bytes)
        .unwrap();
    builder
        .add_field("http.request.version", Type::Bytes)
        .unwrap();
    builder.add_field("http.user_agent", Type::Bytes).unwrap();
    builder
        .add_field("http.x_forwarded_for", Type::Bytes)
        .unwrap();

    // Ip Fields
    builder.add_field("ip.src", Type::Ip).unwrap();
    builder.add_field("ip.src.asnum", Type::Int).unwrap();
    // Deprecated alias for ip.src.asnum
    builder.add_field("ip.geoip.asnum", Type::Int).unwrap();
    builder.add_field("ip.src.city", Type::Bytes).unwrap();
    builder.add_field("ip.src.continent", Type::Bytes).unwrap();
    // Deprecated alias for ip.src.continent
    builder
        .add_field("ip.geoip.continent", Type::Bytes)
        .unwrap();
    builder.add_field("ip.src.country", Type::Bytes).unwrap();
    // Deprecated alias for ip.src.country
    builder.add_field("ip.geoip.country", Type::Bytes).unwrap();
    builder
        .add_field("ip.src.is_in_european_union", Type::Bool)
        .unwrap();
    // Deprecated alias for ip.src.is_in_european_union
    builder
        .add_field("ip.geoip.is_in_european_union", Type::Bool)
        .unwrap();
    builder.add_field("ip.src.lat", Type::Bytes).unwrap();
    builder.add_field("ip.src.lon", Type::Bytes).unwrap();
    builder.add_field("ip.src.metro_code", Type::Bytes).unwrap();
    builder
        .add_field("ip.src.postal_code", Type::Bytes)
        .unwrap();
    builder.add_field("ip.src.region", Type::Bytes).unwrap();
    builder
        .add_field("ip.src.region_code", Type::Bytes)
        .unwrap();
    builder
        .add_field("ip.src.subdivision_1_iso_code", Type::Bytes)
        .unwrap();
    // Deprecated alias for ip.src.subdivision_1_iso_code
    builder
        .add_field("ip.geoip.subdivision_1_iso_code", Type::Bytes)
        .unwrap();
    builder
        .add_field("ip.src.subdivision_2_iso_code", Type::Bytes)
        .unwrap();
    // Deprecated alias for ip.src.subdivision_2_iso_code
    builder
        .add_field("ip.geoip.subdivision_2_iso_code", Type::Bytes)
        .unwrap();

    // Raw Fields
    builder
        .add_field("raw.http.request.full_uri", Type::Bytes)
        .unwrap();
    builder
        .add_field("raw.http.request.uri", Type::Bytes)
        .unwrap();
    builder
        .add_field(
            "raw.http.request.uri.args",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "raw.http.request.uri.args.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "raw.http.request.uri.args.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("raw.http.request.uri.path", Type::Bytes)
        .unwrap();
    builder
        .add_field("raw.http.request.uri.path.extension", Type::Bytes)
        .unwrap();
    builder
        .add_field("raw.http.request.uri.query", Type::Bytes)
        .unwrap();

    // Ssl Fields
    builder.add_field("ssl", Type::Bool).unwrap();

    // True Fields
    builder.add_field("true", Type::Bool).unwrap();

    // Raw Fields
    builder
        .add_field(
            "raw.http.request.headers",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "raw.http.request.headers.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "raw.http.request.headers.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();

    // GENERATED_SCHEMA_FIELDS_COMMON_END
}

fn add_bulk_redirect_fields(
    #[allow(unused)] builder: &mut wirefilter::SchemeBuilder,
    #[allow(unused)] is_response: bool,
) {
    // GENERATED_SCHEMA_FIELDS_BULK_REDIRECTS_START
    // Standard field definitions

    // GENERATED_SCHEMA_FIELDS_BULK_REDIRECTS_END
}

fn add_request_header_fields(
    #[allow(unused)] builder: &mut wirefilter::SchemeBuilder,
    #[allow(unused)] is_response: bool,
) {
    // GENERATED_SCHEMA_FIELDS_REQUEST_HEADER_START
    // Standard field definitions
    // Cf Fields
    builder
        .add_field("cf.bot_management.corporate_proxy", Type::Bool)
        .unwrap();
    builder
        .add_field(
            "cf.bot_management.detection_ids",
            Type::Array(Type::Int.into()),
        )
        .unwrap();
    builder
        .add_field("cf.bot_management.ja3_hash", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.bot_management.ja4", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.bot_management.js_detection.passed", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.bot_management.score", Type::Int)
        .unwrap();
    builder
        .add_field("cf.bot_management.signed_agent", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.bot_management.static_resource", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.bot_management.verified_bot", Type::Bool)
        .unwrap();
    builder.add_field("cf.client.bot", Type::Bool).unwrap();
    builder
        .add_field("cf.verified_bot_category", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.waf.auth_detected", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.waf.credential_check.password_leaked", Type::Bool)
        .unwrap();
    builder
        .add_field(
            "cf.waf.credential_check.username_and_password_leaked",
            Type::Bool,
        )
        .unwrap();
    builder
        .add_field("cf.waf.credential_check.username_leaked", Type::Bool)
        .unwrap();
    builder
        .add_field(
            "cf.waf.credential_check.username_password_similar",
            Type::Bool,
        )
        .unwrap();
    builder.add_field("cf.waf.score", Type::Int).unwrap();
    builder
        .add_field("cf.waf.score.class", Type::Bytes)
        .unwrap();
    builder.add_field("cf.waf.score.rce", Type::Int).unwrap();
    builder.add_field("cf.waf.score.sqli", Type::Int).unwrap();
    builder.add_field("cf.waf.score.xss", Type::Int).unwrap();

    // Http Fields
    builder
        .add_field(
            "http.request.body.form",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.form.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.form.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.content_dispositions",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.content_transfer_encodings",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.content_types",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.filenames",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.names",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("http.request.body.raw", Type::Bytes)
        .unwrap();
    builder
        .add_field("http.request.body.size", Type::Int)
        .unwrap();
    builder
        .add_field("http.request.body.truncated", Type::Bool)
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.aud",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.aud.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.aud.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iat.sec",
            Type::Map(Type::Array(Type::Int.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iat.sec.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iat.sec.values",
            Type::Array(Type::Int.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iss",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iss.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iss.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.jti",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.jti.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.jti.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.nbf.sec",
            Type::Map(Type::Array(Type::Int.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.nbf.sec.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.nbf.sec.values",
            Type::Array(Type::Int.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.sub",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.sub.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.sub.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();

    // GENERATED_SCHEMA_FIELDS_REQUEST_HEADER_END
}

fn add_response_header_fields(
    #[allow(unused)] builder: &mut wirefilter::SchemeBuilder,
    #[allow(unused)] is_response: bool,
) {
    // GENERATED_SCHEMA_FIELDS_RESPONSE_HEADER_START
    // Standard field definitions
    // Cf Fields
    builder
        .add_field("cf.bot_management.corporate_proxy", Type::Bool)
        .unwrap();
    builder
        .add_field(
            "cf.bot_management.detection_ids",
            Type::Array(Type::Int.into()),
        )
        .unwrap();
    builder
        .add_field("cf.bot_management.ja3_hash", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.bot_management.ja4", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.bot_management.js_detection.passed", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.bot_management.score", Type::Int)
        .unwrap();
    builder
        .add_field("cf.bot_management.signed_agent", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.bot_management.static_resource", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.bot_management.verified_bot", Type::Bool)
        .unwrap();
    builder.add_field("cf.client.bot", Type::Bool).unwrap();
    if is_response {
        builder
            .add_field("cf.response.1xxx_code", Type::Int)
            .unwrap();
    }
    if is_response {
        builder
            .add_field("cf.response.error_type", Type::Bytes)
            .unwrap();
    }
    if is_response {
        builder
            .add_field("cf.timings.edge_msec", Type::Int)
            .unwrap();
    }
    if is_response {
        builder
            .add_field("cf.timings.origin_ttfb_msec", Type::Int)
            .unwrap();
    }
    if is_response {
        builder
            .add_field("cf.timings.worker_msec", Type::Int)
            .unwrap();
    }
    builder
        .add_field("cf.verified_bot_category", Type::Bytes)
        .unwrap();

    // Http Fields
    builder
        .add_field(
            "http.request.body.form",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.form.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.form.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.content_dispositions",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.content_transfer_encodings",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.content_types",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.filenames",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.names",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("http.request.body.raw", Type::Bytes)
        .unwrap();
    builder
        .add_field("http.request.body.size", Type::Int)
        .unwrap();
    builder
        .add_field("http.request.body.truncated", Type::Bool)
        .unwrap();
    if is_response {
        builder.add_field("http.response.code", Type::Int).unwrap();
    }
    if is_response {
        builder
            .add_field("http.response.content_type.media_type", Type::Bytes)
            .unwrap();
    }
    if is_response {
        builder
            .add_field(
                "http.response.headers",
                Type::Map(Type::Array(Type::Bytes.into()).into()),
            )
            .unwrap();
    }
    if is_response {
        builder
            .add_field(
                "http.response.headers.names",
                Type::Array(Type::Bytes.into()),
            )
            .unwrap();
    }
    if is_response {
        builder
            .add_field(
                "http.response.headers.values",
                Type::Array(Type::Bytes.into()),
            )
            .unwrap();
    }
    // Raw Fields
    if is_response {
        builder
            .add_field(
                "raw.http.response.headers",
                Type::Map(Type::Array(Type::Bytes.into()).into()),
            )
            .unwrap();
    }
    if is_response {
        builder
            .add_field(
                "raw.http.response.headers.names",
                Type::Array(Type::Bytes.into()),
            )
            .unwrap();
    }
    if is_response {
        builder
            .add_field(
                "raw.http.response.headers.values",
                Type::Array(Type::Bytes.into()),
            )
            .unwrap();
    }
    // GENERATED_SCHEMA_FIELDS_RESPONSE_HEADER_END
}

fn add_url_rewrite_fields(
    #[allow(unused)] builder: &mut wirefilter::SchemeBuilder,
    #[allow(unused)] is_response: bool,
) {
    // GENERATED_SCHEMA_FIELDS_URL_REWRITE_START
    // Standard field definitions

    // GENERATED_SCHEMA_FIELDS_URL_REWRITE_END
}

fn add_all_fields(
    #[allow(unused)] builder: &mut wirefilter::SchemeBuilder,
    #[allow(unused)] is_response: bool,
) {
    // GENERATED_SCHEMA_FIELDS_START
    // Standard field definitions
    // Cf Fields
    builder
        .add_field("cf.api_gateway.auth_id_present", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.api_gateway.fallthrough_detected", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.api_gateway.request_violates_schema", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.bot_management.corporate_proxy", Type::Bool)
        .unwrap();
    builder
        .add_field(
            "cf.bot_management.detection_ids",
            Type::Array(Type::Int.into()),
        )
        .unwrap();
    builder
        .add_field("cf.bot_management.ja3_hash", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.bot_management.ja4", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.bot_management.js_detection.passed", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.bot_management.score", Type::Int)
        .unwrap();
    builder
        .add_field("cf.bot_management.signed_agent", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.bot_management.static_resource", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.bot_management.verified_bot", Type::Bool)
        .unwrap();
    builder.add_field("cf.client.bot", Type::Bool).unwrap();
    builder
        .add_field(
            "cf.llm.prompt.custom_topic_categories",
            Type::Map(Type::Int.into()),
        )
        .unwrap();
    builder
        .add_field("cf.llm.prompt.detected", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.llm.prompt.injection_score", Type::Int)
        .unwrap();
    builder
        .add_field(
            "cf.llm.prompt.pii_categories",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("cf.llm.prompt.pii_detected", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.llm.prompt.token_count", Type::Int)
        .unwrap();
    builder
        .add_field(
            "cf.llm.prompt.unsafe_topic_categories",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("cf.llm.prompt.unsafe_topic_detected", Type::Bool)
        .unwrap();
    if is_response {
        builder
            .add_field("cf.response.1xxx_code", Type::Int)
            .unwrap();
    }
    if is_response {
        builder
            .add_field("cf.response.error_type", Type::Bytes)
            .unwrap();
    }
    builder.add_field("cf.threat_score", Type::Int).unwrap();
    if is_response {
        builder
            .add_field("cf.timings.edge_msec", Type::Int)
            .unwrap();
    }
    if is_response {
        builder
            .add_field("cf.timings.origin_ttfb_msec", Type::Int)
            .unwrap();
    }
    if is_response {
        builder
            .add_field("cf.timings.worker_msec", Type::Int)
            .unwrap();
    }
    builder
        .add_field("cf.tls_ciphers_sha1", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.verified_bot_category", Type::Bytes)
        .unwrap();
    builder
        .add_field("cf.waf.auth_detected", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.waf.content_scan.has_failed", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.waf.content_scan.has_malicious_obj", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.waf.content_scan.has_obj", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.waf.content_scan.num_malicious_obj", Type::Int)
        .unwrap();
    builder
        .add_field("cf.waf.content_scan.num_obj", Type::Int)
        .unwrap();
    builder
        .add_field(
            "cf.waf.content_scan.obj_results",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "cf.waf.content_scan.obj_sizes",
            Type::Array(Type::Int.into()),
        )
        .unwrap();
    builder
        .add_field(
            "cf.waf.content_scan.obj_types",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("cf.waf.credential_check.password_leaked", Type::Bool)
        .unwrap();
    builder
        .add_field(
            "cf.waf.credential_check.username_and_password_leaked",
            Type::Bool,
        )
        .unwrap();
    builder
        .add_field("cf.waf.credential_check.username_leaked", Type::Bool)
        .unwrap();
    builder
        .add_field(
            "cf.waf.credential_check.username_password_similar",
            Type::Bool,
        )
        .unwrap();
    builder.add_field("cf.waf.score", Type::Int).unwrap();
    builder
        .add_field("cf.waf.score.class", Type::Bytes)
        .unwrap();
    builder.add_field("cf.waf.score.rce", Type::Int).unwrap();
    builder.add_field("cf.waf.score.sqli", Type::Int).unwrap();
    builder.add_field("cf.waf.score.xss", Type::Int).unwrap();

    // Http Fields
    builder
        .add_field(
            "http.request.body.form",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.form.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.form.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("http.request.body.mime", Type::Bytes)
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.content_dispositions",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.content_transfer_encodings",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.content_types",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.filenames",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.names",
            Type::Array(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.body.multipart.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("http.request.body.raw", Type::Bytes)
        .unwrap();
    builder
        .add_field("http.request.body.size", Type::Int)
        .unwrap();
    builder
        .add_field("http.request.body.truncated", Type::Bool)
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.aud",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.aud.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.aud.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iat.sec",
            Type::Map(Type::Array(Type::Int.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iat.sec.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iat.sec.values",
            Type::Array(Type::Int.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iss",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iss.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.iss.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.jti",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.jti.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.jti.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.nbf.sec",
            Type::Map(Type::Array(Type::Int.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.nbf.sec.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.nbf.sec.values",
            Type::Array(Type::Int.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.sub",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.sub.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.request.jwt.claims.sub.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    if is_response {
        builder.add_field("http.response.code", Type::Int).unwrap();
    }
    if is_response {
        builder
            .add_field("http.response.content_type.media_type", Type::Bytes)
            .unwrap();
    }
    if is_response {
        builder
            .add_field(
                "http.response.headers",
                Type::Map(Type::Array(Type::Bytes.into()).into()),
            )
            .unwrap();
    }
    if is_response {
        builder
            .add_field(
                "http.response.headers.names",
                Type::Array(Type::Bytes.into()),
            )
            .unwrap();
    }
    if is_response {
        builder
            .add_field(
                "http.response.headers.values",
                Type::Array(Type::Bytes.into()),
            )
            .unwrap();
    }
    // Ip Fields
    builder
        .add_field("ip.src.timezone.name", Type::Bytes)
        .unwrap();

    // Raw Fields
    if is_response {
        builder
            .add_field(
                "raw.http.response.headers",
                Type::Map(Type::Array(Type::Bytes.into()).into()),
            )
            .unwrap();
    }
    if is_response {
        builder
            .add_field(
                "raw.http.response.headers.names",
                Type::Array(Type::Bytes.into()),
            )
            .unwrap();
    }
    if is_response {
        builder
            .add_field(
                "raw.http.response.headers.values",
                Type::Array(Type::Bytes.into()),
            )
            .unwrap();
    }
    // GENERATED_SCHEMA_FIELDS_END
}

/// Per-phase scheme mapping. Currently each phase uses the same base scheme,
/// but this allows switching to phase-specific schemes later without API churn.
pub static SCHEMES: LazyLock<HashMap<Phase, Scheme>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    for p in Phase::iter() {
        m.insert(p, build_scheme(p));
    }
    m
});
