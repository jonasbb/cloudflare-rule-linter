use super::*;
use std::collections::BTreeMap;
use std::sync::LazyLock;
use wirefilter::Visitor;

static DEPRECATIONS: LazyLock<BTreeMap<&'static str, &'static str>> = LazyLock::new(|| {
    BTreeMap::from([
        ("ip.geoip.asnum", "ip.src.asnum"),
        ("ip.geoip.continent", "ip.src.continent"),
        ("ip.geoip.country", "ip.src.country"),
        (
            "ip.geoip.is_in_european_union",
            "ip.src.is_in_european_union",
        ),
        (
            "ip.geoip.subdivision_1_iso_code",
            "ip.src.subdivision_1_iso_code",
        ),
        (
            "ip.geoip.subdivision_2_iso_code",
            "ip.src.subdivision_2_iso_code",
        ),
    ])
});

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct DeprecatedField;

impl Lint for DeprecatedField {
    fn name(&self) -> &'static str {
        "deprecated_field"
    }

    fn category(&self) -> Category {
        Category::Deprecated
    }

    fn lint(&self, ast: &FilterAst) -> String {
        struct DeprecatedFieldVisitor {
            result: String,
        }

        let mut visitor = DeprecatedFieldVisitor {
            result: String::new(),
        };

        impl Visitor<'_> for DeprecatedFieldVisitor {
            fn visit_field(&mut self, field: &'_ wirefilter::Field) {
                let name = field.name();
                if let Some(new_name) = DEPRECATIONS.get(name) {
                    // Use the field name in the message. We don't always have the surrounding
                    // comparison expression here, so keep the message focused on the field.
                    self.result += &format!(
                        "Found usage of deprecated field: {name}\nThe value `{name}` should be \
                         replaced with `{}`.\n",
                        new_name
                    );
                }
            }
        }

        ast.walk(&mut visitor);
        visitor.result
    }
}

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::*;

    static LINTER: std::sync::LazyLock<Linter> = std::sync::LazyLock::new(|| {
        let mut linter = Linter::new();
        linter.config = LinterConfig::default_disable_all_lints();
        linter.config.lints.enable_lints = vec![DeprecatedField.name().into()];
        linter
    });

    #[test]
    fn test_ip_geo_field_detected() {
        expect_lint_message(
            &LINTER,
            r#"ip.geoip.asnum eq 1"#,
            expect![[r#"
                Found usage of deprecated field: ip.geoip.asnum
                The value `ip.geoip.asnum` should be replaced with `ip.src.asnum`.
            "#]],
        );

        expect_lint_message(
            &LINTER,
            r#"ip.geoip.country eq "US""#,
            expect![[r#"
                Found usage of deprecated field: ip.geoip.country
                The value `ip.geoip.country` should be replaced with `ip.src.country`.
            "#]],
        );
    }

    #[test]
    fn test_ip_geo_field_not_detected() {
        assert_no_lint_message(&LINTER, r#"ip.src eq 1.2.3.4"#);
        assert_no_lint_message(&LINTER, r#"http.host eq "example.com""#);
    }
}
