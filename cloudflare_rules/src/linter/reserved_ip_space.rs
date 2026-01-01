use super::*;
use crate::ast_printer::AstPrintVisitor;
use std::net::{Ipv4Addr, Ipv6Addr};
use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, ExplicitIpRange, IpRange, RhsValue, RhsValues, Visitor,
};

// Define reserved IPv4 ranges (from IANA / Wikipedia Reserved IP addresses)
const RESERVED_IPV4_RANGES: &[(Ipv4Addr, Ipv4Addr)] = &[
    // Special / Reserved
    (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 255, 255, 255)), // 0.0.0.0/8
    (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 255, 255, 255)), // 10.0.0.0/8 (RFC1918)
    (
        Ipv4Addr::new(100, 64, 0, 0),
        Ipv4Addr::new(100, 127, 255, 255),
    ), // 100.64.0.0/10 (CGN)
    (
        Ipv4Addr::new(127, 0, 0, 0),
        Ipv4Addr::new(127, 255, 255, 255),
    ), // 127.0.0.0/8 (loopback)
    (
        Ipv4Addr::new(169, 254, 0, 0),
        Ipv4Addr::new(169, 254, 255, 255),
    ), // 169.254.0.0/16 (link local)
    (
        Ipv4Addr::new(172, 16, 0, 0),
        Ipv4Addr::new(172, 31, 255, 255),
    ), // 172.16.0.0/12 (RFC1918)
    (Ipv4Addr::new(192, 0, 0, 0), Ipv4Addr::new(192, 0, 0, 255)), // 192.0.0.0/24 (IANA)
    (Ipv4Addr::new(192, 0, 2, 0), Ipv4Addr::new(192, 0, 2, 255)), // 192.0.2.0/24 (TEST-NET-1)
    (
        Ipv4Addr::new(192, 88, 99, 0),
        Ipv4Addr::new(192, 88, 99, 255),
    ), // 192.88.99.0/24 (6to4 relay)
    (
        Ipv4Addr::new(192, 168, 0, 0),
        Ipv4Addr::new(192, 168, 255, 255),
    ), // 192.168.0.0/16 (RFC1918)
    (
        Ipv4Addr::new(198, 18, 0, 0),
        Ipv4Addr::new(198, 19, 255, 255),
    ), // 198.18.0.0/15 (benchmark)
    (
        Ipv4Addr::new(198, 51, 100, 0),
        Ipv4Addr::new(198, 51, 100, 255),
    ), // 198.51.100.0/24 (TEST-NET-2)
    (
        Ipv4Addr::new(203, 0, 113, 0),
        Ipv4Addr::new(203, 0, 113, 255),
    ), // 203.0.113.0/24 (TEST-NET-3)
    (
        Ipv4Addr::new(224, 0, 0, 0),
        Ipv4Addr::new(239, 255, 255, 255),
    ), // 224.0.0.0/4 (multicast)
    (
        Ipv4Addr::new(240, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
    ), // 240.0.0.0/4 (future/reserved)
];

// Define reserved IPv6 ranges (from IANA / Wikipedia Reserved IP addresses)
const RESERVED_IPV6_RANGES: &[(Ipv6Addr, Ipv6Addr)] = &[
    // Unspecified and loopback
    (
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
    ), // ::/128 unspecified
    (
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
    ), // ::1/128 loopback
    // IPv4-mapped and IPv4-translated ranges
    (
        Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0),
        Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff),
    ), // ::ffff:0:0/96 (IPv4-mapped)
    (
        Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(0x0064, 0xff9b, 0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
    ), // 64:ff9b::/96 (IPv4/IPv6 translation)
    // Link-local, site-local (deprecated), unique local
    (
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(
            0xfebf, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
    ), // fe80::/10 (link-local)
    (
        Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(
            0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
    ), // fc00::/7 (unique local)
    // Multicast
    (
        Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
    ), // ff00::/8 (multicast)
    // Documentation
    (
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(
            0x2001, 0x0db8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
    ), // 2001:db8::/32 (documentation)
    (
        Ipv6Addr::new(0x3fff, 0x0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(
            0x3fff, 0xfff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
    ), // 3fff::/20 (documentation)
    // 6to4, Teredo, ORCHID, deprecated 6bone
    (
        Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(
            0x2002, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
    ), // 2002::/16 (6to4)
    (
        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(0x2001, 0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
    ), // 2001::/32
    // Routing
    (
        Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(
            0x5f00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
    ), // 5f00::/16 (IANA)
    (
        Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(0x0100, 0, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff),
    ), // 100::/64 (IANA)
];

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ReservedIpSpace;

impl Lint for ReservedIpSpace {
    fn name(&self) -> &'static str {
        "reserved_ip_space"
    }

    fn category(&self) -> Category {
        Category::Correctness
    }

    fn lint(&self, ast: &FilterAst) -> String {
        struct ReservedIpSpaceVisitor {
            result: String,
        }

        let mut visitor = ReservedIpSpaceVisitor {
            result: String::new(),
        };

        impl Visitor<'_> for ReservedIpSpaceVisitor {
            fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
                // Check single-IP comparisons (ordering with an IP rhs)
                match &node.op {
                    ComparisonOpExpr::Ordering {
                        rhs: RhsValue::Ip(ip_addr),
                        ..
                    } => match ExplicitIpRange::from(*ip_addr) {
                        ExplicitIpRange::V4(range) => {
                            for (start, end) in RESERVED_IPV4_RANGES {
                                if range.start() <= end && start <= range.end() {
                                    let node_str = AstPrintVisitor::comparison_expr_to_string(node);
                                    let ip_str = AstPrintVisitor::format_ip_range(
                                        &IpRange::Explicit(ExplicitIpRange::V4(range.clone())),
                                    );
                                    self.result += &format!(
                                        "Found usage of reserved IP range: {node_str}\nThe value \
                                         `{ip_str}` is within reserved address space.\n",
                                    );
                                    break;
                                }
                            }
                        }
                        ExplicitIpRange::V6(range) => {
                            for (start, end) in RESERVED_IPV6_RANGES {
                                if range.start() <= end && start <= range.end() {
                                    let node_str = AstPrintVisitor::comparison_expr_to_string(node);
                                    let ip_str = AstPrintVisitor::format_ip_range(
                                        &IpRange::Explicit(ExplicitIpRange::V6(range.clone())),
                                    );
                                    self.result += &format!(
                                        "Found usage of reserved IP range: {node_str}\nThe value \
                                         `{ip_str}` is within reserved address space.\n",
                                    );
                                    break;
                                }
                            }
                        }
                    },
                    ComparisonOpExpr::OneOf(RhsValues::Ip(ip_ranges)) => {
                        for ip in ip_ranges {
                            let explicit = ExplicitIpRange::from(ip.clone());
                            match explicit {
                                ExplicitIpRange::V4(range) => {
                                    for (start, end) in RESERVED_IPV4_RANGES {
                                        if range.start() <= end && start <= range.end() {
                                            let node_str =
                                                AstPrintVisitor::comparison_expr_to_string(node);
                                            let ip_str = AstPrintVisitor::format_ip_range(ip);
                                            self.result += &format!(
                                                "Found usage of reserved IP range: \
                                                 {node_str}\nThe value `{ip_str}` is within \
                                                 reserved address space.\n",
                                            );
                                            break;
                                        }
                                    }
                                }
                                ExplicitIpRange::V6(range) => {
                                    for (start, end) in RESERVED_IPV6_RANGES {
                                        if range.start() <= end && start <= range.end() {
                                            let node_str =
                                                AstPrintVisitor::comparison_expr_to_string(node);
                                            let ip_str = AstPrintVisitor::format_ip_range(ip);
                                            self.result += &format!(
                                                "Found usage of reserved IP range: \
                                                 {node_str}\nThe value `{ip_str}` is within \
                                                 reserved address space.\n",
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }

                self.visit_value_expr(&node.lhs);
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

    static LINTER: LazyLock<Linter> = LazyLock::new(|| {
        let mut linter = Linter::new();
        linter.config = LinterConfig::default_disable_all_lints();
        linter.config.lints.enable_lints = vec![ReservedIpSpace.name().into()];
        linter
    });

    #[test]
    fn test_reserved_ip_space() {
        expect_lint_message(
            &LINTER,
            r#"ip.src eq 127.0.0.1"#,
            expect![[r#"
                Found usage of reserved IP range: ip.src eq 127.0.0.1
                The value `127.0.0.1` is within reserved address space.
            "#]],
        );
        expect_lint_message(
            &LINTER,
            r#"ip.src in {10.0.0.0/8 8.8.8.8}"#,
            expect![[r#"
                Found usage of reserved IP range: ip.src in {10.0.0.0/8 8.8.8.8}
                The value `10.0.0.0/8` is within reserved address space.
            "#]],
        );
        expect_lint_message(
            &LINTER,
            r#"ip.src in { fe80:0:0:1234::/96 }"#,
            expect![[r#"
                Found usage of reserved IP range: ip.src in {fe80:0:0:1234::/96}
                The value `fe80:0:0:1234::/96` is within reserved address space.
            "#]],
        );

        assert_no_lint_message(&LINTER, r#"ip.src eq 8.8.8.8"#);
    }
}
