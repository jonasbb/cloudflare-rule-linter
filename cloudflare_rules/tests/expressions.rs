//! Tests for basic expressions for Cloudflare Rules
//!
//! These tests ensure that normal expressions can be parsed correctly.

use cloudflare_rules::{Phase, SCHEMES};

#[track_caller]
fn assert_can_parse(expr: &str) {
    assert_can_parse_phase(Phase::Maximum, expr);
}

#[track_caller]
fn assert_can_parse_phase(phase: Phase, expr: &str) {
    SCHEMES
        .get(&phase)
        .expect("SCHEMES is always set")
        .parse(expr)
        .expect("All wirefilter rules in the test must be valid expressions.");
}

#[test]
fn test_coalesce_function() {
    // https://developers.cloudflare.com/changelog/post/2026-10-01-coalesce-function/
    assert_can_parse(
        r#"http.request.uri.path eq coalesce(http.request.uri.args["expected_path"][0], "/")"#,
    );
}

#[test]
fn test_dynamic_values() {
    // https://developers.cloudflare.com/changelog/post/2026-10-01-dynamic-comparison-values/
    assert_can_parse(r#"http.request.uri.path ne raw.http.request.uri.path"#);

    // https://developers.cloudflare.com/ruleset-engine/rules-language/operators/#compare-dynamic-values
    assert_can_parse(r#"http.request.uri.path ne raw.http.request.uri.path"#);
    assert_can_parse(r#"len(http.request.uri.path) gt len(http.request.uri.query)"#);

    // https://developers.cloudflare.com/ruleset-engine/rules-language/values/#missing-values
    assert_can_parse(r#"http.request.uri.args["first"][0] eq http.request.uri.args["second"][0]"#);
    assert_can_parse(
        r#"coalesce(http.request.uri.args["first"][0], "") eq http.request.uri.args["second"][0]"#,
    );
}

#[test]
fn test_map_examples() {
    // https://developers.cloudflare.com/ruleset-engine/rules-language/values/#examples-1
    assert_can_parse(r#"all(len(http.request.uri.args["filter"][*])[*] in {3 4})"#);
    assert_can_parse(r#"all(not len(http.request.uri.args["filter"][*])[*] in {3 4})"#);
    assert_can_parse(r#"len(http.request.uri.args["filter"]) >= 0"#);
    assert_can_parse(r#"not len(http.request.uri.args["order"]) >= 0"#);
}
