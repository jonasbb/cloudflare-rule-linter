waf_rules {
    test_negated_condition {
        rule_disable_category {
            // cfrl: -deprecated
            expression = "not ( ip.geoip.country eq \"T1\" )"
        }
        rule_disable_rule {
            // cfrl: -negated_comparison
            expression = "not ( ip.geoip.country eq \"T1\" )"
        }
        rule_disable_category_enable_lint {
            // cfrl: -deprecated, +deprecated_field
            expression = "not ( ip.geoip.country eq \"T1\" )"
        }
    }
}
