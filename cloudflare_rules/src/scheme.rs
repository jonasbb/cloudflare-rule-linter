// Transform functions implementations

use wirefilter::{
    FunctionArgs, LhsValue, Scheme, SimpleFunctionArgKind as FunctionArgKind,
    SimpleFunctionDefinition, SimpleFunctionImpl, SimpleFunctionOptParam, SimpleFunctionParam,
    Type,
};

fn placeholder_fn<'a>(_args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    unimplemented!()
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NumList {}

impl wirefilter::ListDefinition for NumList {
    fn matcher_from_json_value(
        &self,
        _: Type,
        _: serde_json::Value,
    ) -> Result<Box<dyn wirefilter::ListMatcher>, serde_json::Error> {
        Ok(Box::new(NumList {}))
    }

    fn new_matcher(&self) -> Box<dyn wirefilter::ListMatcher> {
        Box::new(NumList {})
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

    fn to_json_value(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    fn clear(&mut self) {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IpList {}

impl wirefilter::ListDefinition for IpList {
    fn matcher_from_json_value(
        &self,
        _: Type,
        _: serde_json::Value,
    ) -> Result<Box<dyn wirefilter::ListMatcher>, serde_json::Error> {
        Ok(Box::new(IpList {}))
    }

    fn new_matcher(&self) -> Box<dyn wirefilter::ListMatcher> {
        Box::new(IpList {})
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

    fn to_json_value(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    fn clear(&mut self) {}
}

/// Generate the default scheme matching the one Cloudflare uses
///
/// This includes fields, functions, and lists.
pub(crate) fn build_scheme() -> Scheme {
    let mut builder = wirefilter::SchemeBuilder::new();

    // Add custom lists
    builder.add_list(Type::Int, NumList {}).unwrap();
    builder.add_list(Type::Ip, IpList {}).unwrap();

    // Add standard functions
    builder
        .add_function("any", wirefilter::AnyFunction {})
        .unwrap();
    builder
        .add_function("all", wirefilter::AllFunction {})
        .unwrap();
    builder
        .add_function("cidr", wirefilter::CIDRFunction {})
        .unwrap();
    builder
        .add_function(
            "cidr6",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Field,
                        val_type: Type::Ip,
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Literal,
                        val_type: Type::Int,
                    },
                ],
                opt_params: vec![],
                return_type: Type::Ip,
                implementation: SimpleFunctionImpl::new(placeholder_fn),
            },
        )
        .unwrap();
    builder
        .add_function("concat", wirefilter::ConcatFunction {})
        .unwrap();
    builder
        .add_function("decode_base64", wirefilter::DecodeBase64Function {})
        .unwrap();
    builder
        .add_function("ends_with", wirefilter::EndsWithFunction {})
        .unwrap();
    builder
        .add_function(
            "join",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Field,
                        val_type: Type::Array(Type::Bytes.into()),
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Literal,
                        val_type: Type::Bytes,
                    },
                ],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(placeholder_fn),
            },
        )
        .unwrap();
    builder
        .add_function(
            "has_key",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Field,
                        // TODO: Should be Map<T>
                        val_type: Type::Map(Type::Bytes.into()),
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Both,
                        val_type: Type::Bytes,
                    },
                ],
                opt_params: vec![],
                return_type: Type::Bool,
                implementation: SimpleFunctionImpl::new(placeholder_fn),
            },
        )
        .unwrap();
    builder
        .add_function(
            "has_value",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Field,
                        // TODO: Should be Map<T>|Array<T>
                        val_type: Type::Map(Type::Bytes.into()),
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Both,
                        // TODO: Should be T
                        val_type: Type::Bytes,
                    },
                ],
                opt_params: vec![],
                return_type: Type::Bool,
                implementation: SimpleFunctionImpl::new(placeholder_fn),
            },
        )
        .unwrap();
    builder
        .add_function("len", wirefilter::LenFunction {})
        .unwrap();
    // TODO lookup_json_integer
    // TODO lookup_json_string
    builder
        .add_function("lower", wirefilter::LowerFunction {})
        .unwrap();
    builder
        .add_function(
            "regex_replace",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Both,
                        val_type: Type::Bytes,
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Literal,
                        val_type: Type::Bytes,
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Literal,
                        val_type: Type::Bytes,
                    },
                ],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(placeholder_fn),
            },
        )
        .unwrap();
    builder
        .add_function("remove_bytes", wirefilter::RemoveBytesFunction {})
        .unwrap();
    builder
        .add_function(
            "remove_query_args",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Field,
                        val_type: Type::Bytes,
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Literal,
                        val_type: Type::Bytes,
                    },
                    // TODO Arbitrary many arguments supported
                ],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(placeholder_fn),
            },
        )
        .unwrap();
    builder
        .add_function(
            "split",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Field,
                        val_type: Type::Bytes,
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Literal,
                        val_type: Type::Bytes,
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Literal,
                        val_type: Type::Int,
                    },
                ],
                opt_params: vec![],
                return_type: Type::Array(Type::Bytes.into()),
                implementation: SimpleFunctionImpl::new(placeholder_fn),
            },
        )
        .unwrap();
    builder
        .add_function("starts_with", wirefilter::StartsWithFunction {})
        .unwrap();
    builder
        .add_function("substring", wirefilter::SubstringFunction {})
        .unwrap();
    builder
        .add_function("to_string", wirefilter::ToStringFunction {})
        .unwrap();
    builder
        .add_function("upper", wirefilter::UpperFunction {})
        .unwrap();
    builder
        .add_function("url_decode", wirefilter::UrlDecodeFunction {})
        .unwrap();
    builder
        .add_function(
            "uuidv4",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam {
                    arg_kind: FunctionArgKind::Field,
                    val_type: Type::Bytes,
                }],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(placeholder_fn),
            },
        )
        .unwrap();
    builder
        .add_function(
            "wildcard_replace",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Field,
                        val_type: Type::Bytes,
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Literal,
                        val_type: Type::Bytes,
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Literal,
                        val_type: Type::Bytes,
                    },
                ],
                opt_params: vec![SimpleFunctionOptParam {
                    arg_kind: FunctionArgKind::Literal,
                    default_value: LhsValue::Bytes(b"".into()),
                }],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(placeholder_fn),
            },
        )
        .unwrap();
    builder
        .add_function(
            "is_timed_hmac_valid_v0",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Literal,
                        val_type: Type::Bytes,
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Both,
                        val_type: Type::Bytes,
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Literal,
                        val_type: Type::Int,
                    },
                    SimpleFunctionParam {
                        arg_kind: FunctionArgKind::Both,
                        val_type: Type::Int,
                    },
                ],
                opt_params: vec![
                    SimpleFunctionOptParam {
                        arg_kind: FunctionArgKind::Literal,
                        default_value: LhsValue::Int(0),
                    },
                    SimpleFunctionOptParam {
                        arg_kind: FunctionArgKind::Literal,
                        default_value: LhsValue::Bytes(b"".into()),
                    },
                ],
                return_type: Type::Bool,
                implementation: SimpleFunctionImpl::new(placeholder_fn),
            },
        )
        .unwrap();

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
        .add_field("cf.bot_management.static_resource", Type::Bool)
        .unwrap();
    builder
        .add_field("cf.bot_management.verified_bot", Type::Bool)
        .unwrap();
    builder.add_field("cf.client.bot", Type::Bool).unwrap();
    builder.add_field("cf.edge.client_tcp", Type::Bool).unwrap();
    builder.add_field("cf.edge.server_ip", Type::Ip).unwrap();
    builder.add_field("cf.edge.server_port", Type::Int).unwrap();
    builder
        .add_field("cf.hostname.metadata", Type::Bytes)
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
        .add_field(
            "cf.llm.prompt.unsafe_topic_categories",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field("cf.llm.prompt.unsafe_topic_detected", Type::Bool)
        .unwrap();
    builder.add_field("cf.random_seed", Type::Bytes).unwrap();
    builder.add_field("cf.ray_id", Type::Bytes).unwrap();
    builder
        .add_field("cf.response.1xxx_code", Type::Int)
        .unwrap();
    builder
        .add_field("cf.response.error_type", Type::Bytes)
        .unwrap();
    builder.add_field("cf.threat_score", Type::Int).unwrap();
    builder
        .add_field("cf.timings.client_tcp_rtt_msec", Type::Int)
        .unwrap();
    builder.add_field("cf.tls_cipher", Type::Bytes).unwrap();
    builder
        .add_field("cf.tls_ciphers_sha1", Type::Bytes)
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
    builder.add_field("http.response.code", Type::Int).unwrap();
    builder
        .add_field("http.response.content_type.media_type", Type::Bytes)
        .unwrap();
    builder
        .add_field(
            "http.response.headers",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.response.headers.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "http.response.headers.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder.add_field("http.user_agent", Type::Bytes).unwrap();
    builder
        .add_field("http.x_forwarded_for", Type::Bytes)
        .unwrap();

    // Ip Fields
    builder.add_field("ip.src", Type::Ip).unwrap();
    builder.add_field("ip.src.asnum", Type::Int).unwrap();
    // Old name for ip.src.asnum
    builder.add_field("ip.geoip.asnum", Type::Int).unwrap();
    builder.add_field("ip.src.city", Type::Bytes).unwrap();
    builder.add_field("ip.src.continent", Type::Bytes).unwrap();
    // Old name for ip.src.continent
    builder
        .add_field("ip.geoip.continent", Type::Bytes)
        .unwrap();
    builder.add_field("ip.src.country", Type::Bytes).unwrap();
    // Old name for ip.src.country
    builder.add_field("ip.geoip.country", Type::Bytes).unwrap();
    builder
        .add_field("ip.src.is_in_european_union", Type::Bool)
        .unwrap();
    // Old name for ip.src.is_in_european_union
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
    // Old name for ip.src.subdivision_1_iso_code
    builder
        .add_field("ip.geoip.subdivision_1_iso_code", Type::Bytes)
        .unwrap();
    builder
        .add_field("ip.src.subdivision_2_iso_code", Type::Bytes)
        .unwrap();
    // Old name for ip.src.subdivision_2_iso_code
    builder
        .add_field("ip.geoip.subdivision_2_iso_code", Type::Bytes)
        .unwrap();
    builder
        .add_field("ip.src.timezone.name", Type::Bytes)
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
    builder
        .add_field(
            "raw.http.response.headers",
            Type::Map(Type::Array(Type::Bytes.into()).into()),
        )
        .unwrap();
    builder
        .add_field(
            "raw.http.response.headers.names",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();
    builder
        .add_field(
            "raw.http.response.headers.values",
            Type::Array(Type::Bytes.into()),
        )
        .unwrap();

    // Ssl Fields
    builder.add_field("ssl", Type::Bool).unwrap();

    // Matches all incoming traffic
    builder.add_field("true", Type::Bool).unwrap();

    builder.build()
}
