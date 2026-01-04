waf_rules {
    // Some emoji symbols to throw off the byte counts
    // 🏴‍☠️
    test_escaping_is_correctly_accounted {
        rule_no_issue {
            expression = "ssl"
        }
        rule_unknown {
            expression = "unknown"
        }
        rule_unknown_space {
            expression = "  unknown  "
        }
        rule_unknown_newline {
            expression = "\n\nunknown\n\n"
        }
        rule_expression_and_unknown {
            expression = "http.host eq \"com\" and unknown"
        }
        rule_expression_emoji_and_unknown {
            expression = "http.host eq \"🏴‍☠️.com\" and unknown"
        }
        rule_expression_escape_and_unknown {
            expression = "http.host eq \"c\\\"om\" and unknown"
        }
        rule_emoji {
            expression = "http.host eq \"🏴‍☠️.com\" and not http.host eq \"🏴‍☠️.com\""
        }
    }
    test_span_deprecated_field {
        rule0 {
            expression = "ip.geoip.country eq \"T1\""
        }
        rule1 {
            expression = "not ip.geoip.country eq \"T1\""
        }
    }
    test_regex_literal {
        rule0 {
            expression = "not http.host matches \".*\""
        }
    }
    test_illogical_condition {
        rule0 {
            expression = "( ( http.host eq \"A\" and ( ssl and http.host eq \"B\" ) ) )"
        }
    }
    test_negated_condition {
        rule0 {
            expression = "not ( ip.src.country eq \"T1\" ) or not ssl"
        }
        rule_many_trailing_newlines {
            expression = "not ( ip.src.country eq \"T1\" ) or not ssl\n\n\n\n\n\n"
        }
    }
}
