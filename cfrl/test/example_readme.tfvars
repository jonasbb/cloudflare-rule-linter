waf_rules {
    test_negated_condition {
        rule_deprecated_field {
            expression = "ip.geoip.country eq \"T1\""
        }
        rule_duplicate_list_entries {
            expression = "ip.src in {1.0.0.0/8 1.1.0.0/16}"
        }
        rule_reserved_ip_space {
            expression = "ip.src eq 192.168.0.1"
        }
        rule_negated_comparison {
            expression = "not http.host eq \"example.com\""
        }
        rule_regex_raw_string {
            expression = "http.host matches \"example\\.com\""
        }
        rule_illogical_condition {
            expression = "(http.host in { \"example.com\" }) and (http.host eq \"example.org\")"
        }
    }
}
