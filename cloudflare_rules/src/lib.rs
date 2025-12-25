use self::ast_printer::AstPrintVisitor;
use anyhow::{Result, anyhow};
use pyo3::prelude::*;
use std::ops::RangeInclusive;
use std::sync::LazyLock;
use wirefilter::{ComparisonExpr, ExplicitIpRange, OrderingOp, Scheme, UnaryOp};

mod ast_printer;
mod scheme;

static RULE_SCHEME: LazyLock<Scheme> = LazyLock::new(scheme::build_scheme);

/// A Python module implemented in Rust.
#[pymodule]
mod cloudflare_rules {
    use pyo3::prelude::*;

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    fn parse_expression(expr: &str) -> PyResult<String> {
        Ok(super::parse_expression(expr)?)
    }

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    fn get_ast(expr: &str) -> PyResult<String> {
        Ok(super::get_ast(expr)?)
    }
}

pub struct Linter {}

pub enum LintCategory {
    Deprecated,
}

impl Linter {
    pub fn new() -> Self {
        Linter {}
    }

    pub fn lint(&self, ast: &mut wirefilter::FilterAst) -> String {
        let mut res = String::new();
        self.simplify_ast(ast);
        res.push_str(&self.lint_illogical_conditions(ast));
        res.push_str(&self.lint_duplicate_list_entries(ast));
        res.push_str(&self.lint_match_reserved_ip_spaces(ast));
        res.push_str(&self.lint_simplify_negated_comparisons(ast));
        res
    }

    fn lint_simplify_negated_comparisons(&self, ast: &wirefilter::FilterAst) -> String {
        struct NegatedComparisonVisitor {
            result: String,
        }

        let mut visitor = NegatedComparisonVisitor {
            result: String::new(),
        };

        impl wirefilter::Visitor<'_> for NegatedComparisonVisitor {
            fn visit_logical_expr(&mut self, node: &'_ wirefilter::LogicalExpr) {
                if let wirefilter::LogicalExpr::Unary {
                    op: UnaryOp::Not,
                    arg,
                } = node
                    && let wirefilter::LogicalExpr::Comparison(comp @ ComparisonExpr { .. }) =
                        &**arg
                {
                    // Only handle ordering comparisons (eq, ne, lt, le, gt, ge)
                    if let wirefilter::ComparisonOpExpr::Ordering { op, rhs } = &comp.op {
                        use wirefilter::OrderingOp;
                        let suggestion_op = match op {
                            OrderingOp::Equal => Some(OrderingOp::NotEqual),
                            OrderingOp::NotEqual => Some(OrderingOp::Equal),
                            OrderingOp::LessThan => Some(OrderingOp::GreaterThanEqual),
                            OrderingOp::LessThanEqual => Some(OrderingOp::GreaterThan),
                            OrderingOp::GreaterThan => Some(OrderingOp::LessThanEqual),
                            OrderingOp::GreaterThanEqual => Some(OrderingOp::LessThan),
                        };

                        if let Some(sugg) = suggestion_op {
                            let inner = AstPrintVisitor::comparison_expr_to_string(comp);
                            // Reconstruct a ComparisonExpr string with the suggested op
                            // We reuse the AST printer on the original and then replace the operator
                            let sugg_str = match sugg {
                                OrderingOp::Equal => " eq ",
                                OrderingOp::NotEqual => " ne ",
                                OrderingOp::GreaterThanEqual => " ge ",
                                OrderingOp::LessThanEqual => " le ",
                                OrderingOp::GreaterThan => " gt ",
                                OrderingOp::LessThan => " lt ",
                            };

                            // Split on known operator tokens to replace
                            // TODO: add replacements for c style operators
                            let suggested_expr = inner
                                .replace(" eq ", sugg_str)
                                .replace(" ne ", sugg_str)
                                .replace(" gt ", sugg_str)
                                .replace(" lt ", sugg_str)
                                .replace(" ge ", sugg_str)
                                .replace(" le ", sugg_str);

                            self.result += &format!(
                                "Found negated comparison: not {inner}\nConsider simplifying to: \
                                 {suggested_expr}\n",
                            );
                        }
                    }
                }

                self.visit_expr(node);
            }
        }

        ast.walk(&mut visitor);
        visitor.result
    }

    fn lint_match_reserved_ip_spaces(&self, ast: &wirefilter::FilterAst) -> String {
        use std::net::{Ipv4Addr, Ipv6Addr};
        use wirefilter::RhsValue;

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

        struct Rfc1918Visitor {
            result: String,
        }

        let mut visitor = Rfc1918Visitor {
            result: String::new(),
        };

        impl wirefilter::Visitor<'_> for Rfc1918Visitor {
            fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
                // Check single-IP comparisons (ordering with an IP rhs)
                match &node.op {
                    wirefilter::ComparisonOpExpr::Ordering {
                        rhs: RhsValue::Ip(ip_addr),
                        ..
                    } => match ExplicitIpRange::from(*ip_addr) {
                        ExplicitIpRange::V4(range) => {
                            for (start, end) in RESERVED_IPV4_RANGES {
                                if range.start() <= end && start <= range.end() {
                                    let node_str = AstPrintVisitor::comparison_expr_to_string(node);
                                    let ip_str = AstPrintVisitor::format_ip_range(
                                        &wirefilter::IpRange::Explicit(
                                            wirefilter::ExplicitIpRange::V4(range.clone()),
                                        ),
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
                                        &wirefilter::IpRange::Explicit(
                                            wirefilter::ExplicitIpRange::V6(range.clone()),
                                        ),
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
                    wirefilter::ComparisonOpExpr::OneOf(wirefilter::RhsValues::Ip(ip_ranges)) => {
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

    fn simplify_ast(&self, ast: &mut wirefilter::FilterAst) {
        // Parens in the AST are no longer semantically relevant, so we can remove them
        // This will make further analysis easier, as we don't have to consider parens nodes
        //
        // This might reveal further simplification opportunities of combining expressions
        // (e.g., A and (B and C) => A and B and C)

        struct SimplifyVisitor;
        impl wirefilter::VisitorMut<'_> for SimplifyVisitor {
            fn visit_logical_expr(&mut self, node: &'_ mut wirefilter::LogicalExpr) {
                match node {
                    wirefilter::LogicalExpr::Combining { op, items } => {
                        items.iter_mut().for_each(|item| {
                            // Recursively visit each item
                            self.visit_logical_expr(item);
                        });
                        // Check if any item is a combining expression with the same operator
                        let mut new_items = Vec::with_capacity(items.len());
                        for item in items.drain(..) {
                            if let wirefilter::LogicalExpr::Combining {
                                op: inner_op,
                                items: inner_items,
                            } = item
                            {
                                if inner_op == *op {
                                    // Flatten the inner items
                                    new_items.extend(inner_items);
                                } else {
                                    new_items.push(wirefilter::LogicalExpr::Combining {
                                        op: inner_op,
                                        items: inner_items,
                                    });
                                }
                            } else {
                                new_items.push(item);
                            }
                        }
                        *items = new_items;
                    }
                    wirefilter::LogicalExpr::Parenthesized(parenthesized_expr) => {
                        dbg!("Simplifying parenthesized expr");
                        self.visit_logical_expr(&mut parenthesized_expr.expr);
                        // Replace the parenthesized expression with its inner expression
                        *node = parenthesized_expr.expr.clone();
                    }
                    _ => {}
                }
            }
        }

        let mut visitor = SimplifyVisitor;
        ast.walk_mut(&mut visitor);
    }

    fn lint_illogical_conditions(&self, ast: &wirefilter::FilterAst) -> String {
        // Check for illogical conditions
        // A eq 1 and A eq 2 => always false
        // A ne 1 or A ne 2 => always true
        //
        // Special care for different comparisons options
        // A eq 1
        // A in {1 2}
        //
        // A ne 1
        // not A eq 1
        // not A in {1 2}
        //
        // Possible extensions for strings
        // If regex or wildcard matches do not use any placeholders, they could be considered as equal matches

        struct IllogicalConditionsVisitor {
            result: String,
        }
        let mut visitor = IllogicalConditionsVisitor {
            result: String::new(),
        };

        impl wirefilter::Visitor<'_> for IllogicalConditionsVisitor {
            fn visit_logical_expr(&mut self, node: &'_ wirefilter::LogicalExpr) {
                // Check for illogical conditions here
                if let wirefilter::LogicalExpr::Combining { op, items } = node {
                    match op {
                        wirefilter::LogicalOp::And => {
                            // Collect found index expressions to check for duplicates
                            let mut found_lhs = Vec::new();

                            // Check for always false conditions
                            for e in items {
                                // Analyze each expression
                                if let wirefilter::LogicalExpr::Comparison(ComparisonExpr {
                                    lhs,
                                    op:
                                        wirefilter::ComparisonOpExpr::Ordering {
                                            op: OrderingOp::Equal,
                                            ..
                                        }
                                        | wirefilter::ComparisonOpExpr::OneOf(..),
                                }) = e
                                {
                                    if found_lhs.contains(&lhs) {
                                        // Found duplicate equality comparison on same field
                                        // This is always false
                                        let node_str =
                                            AstPrintVisitor::logical_expr_to_string(node);
                                        let lhs_str = AstPrintVisitor::value_expr_to_string(lhs);

                                        self.result += &format!(
                                            "Found illogical condition: {node_str}\nThe value \
                                             `{lhs_str}` is compared for equality multiple times \
                                             in an AND expression.\n"
                                        );
                                    } else {
                                        found_lhs.push(lhs);
                                    }
                                }
                            }
                        }
                        wirefilter::LogicalOp::Or => {
                            // Collect found index expressions to check for duplicates
                            let mut found_lhs = Vec::new();

                            // Check for always true conditions
                            for e in items {
                                dbg!("Analyzing OR expression");
                                // Analyze each expression
                                match e {
                                    wirefilter::LogicalExpr::Comparison(ComparisonExpr {
                                        lhs,
                                        op:
                                            wirefilter::ComparisonOpExpr::Ordering {
                                                op: OrderingOp::NotEqual,
                                                ..
                                            },
                                    }) => {
                                        if found_lhs.contains(&lhs) {
                                            // Found duplicate equality comparison on same field
                                            // This is always false
                                            let node_str =
                                                AstPrintVisitor::logical_expr_to_string(node);
                                            let lhs_str =
                                                AstPrintVisitor::value_expr_to_string(lhs);

                                            self.result += &format!(
                                                "Found illogical condition: {node_str}\nThe value \
                                                 `{lhs_str}` is compared for not-equality \
                                                 multiple times in an OR expression.\n"
                                            );
                                        } else {
                                            found_lhs.push(lhs);
                                        }
                                    }
                                    wirefilter::LogicalExpr::Unary {
                                        op: UnaryOp::Not,
                                        arg,
                                    } => {
                                        if let wirefilter::LogicalExpr::Comparison(
                                            ComparisonExpr {
                                                lhs,
                                                op:
                                                    wirefilter::ComparisonOpExpr::Ordering {
                                                        op: OrderingOp::Equal,
                                                        ..
                                                    }
                                                    | wirefilter::ComparisonOpExpr::OneOf(..),
                                            },
                                        ) = &**arg
                                        {
                                            if found_lhs.contains(&lhs) {
                                                // Found duplicate equality comparison on same field
                                                // This is always false
                                                let node_str =
                                                    AstPrintVisitor::logical_expr_to_string(node);
                                                let lhs_str =
                                                    AstPrintVisitor::value_expr_to_string(lhs);

                                                self.result += &format!(
                                                    "Found illogical condition: {node_str}\nThe \
                                                     value `{lhs_str}` is compared for \
                                                     not-equality multiple times in an OR \
                                                     expression.\n"
                                                );
                                            } else {
                                                found_lhs.push(lhs);
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }

                self.visit_expr(node);
            }
        }

        ast.walk(&mut visitor);
        visitor.result
    }

    fn lint_duplicate_list_entries(&self, ast: &wirefilter::FilterAst) -> String {
        // Check for duplicate entries in list comparisons
        // A in {1 2 2} => duplicate entry 2

        struct DuplicateListEntriesVisitor {
            result: String,
        }
        let mut visitor = DuplicateListEntriesVisitor {
            result: String::new(),
        };

        impl wirefilter::Visitor<'_> for DuplicateListEntriesVisitor {
            fn visit_comparison_expr(&mut self, node: &'_ ComparisonExpr) {
                if let wirefilter::ComparisonOpExpr::OneOf(values) = &node.op {
                    match values {
                        wirefilter::RhsValues::Int(int_ranges) => {
                            for idx in 0..int_ranges.len() {
                                let range_i: RangeInclusive<i64> = int_ranges[idx].clone().into();
                                for range_j in &int_ranges[idx + 1..] {
                                    let range_j: RangeInclusive<i64> = range_j.into();
                                    // Check for overlap
                                    if range_i.start() <= range_j.end()
                                        && range_j.start() <= range_i.end()
                                    {
                                        let node_str =
                                            AstPrintVisitor::comparison_expr_to_string(node);

                                        self.result += &format!(
                                            "Found duplicate entry in list comparison: \
                                             {node_str}\nThe values `{}..{}` and `{}..{}` \
                                             overlap.\n",
                                            range_i.start(),
                                            range_i.end(),
                                            range_j.start(),
                                            range_j.end(),
                                        );
                                    }
                                }
                            }
                        }
                        wirefilter::RhsValues::Ip(ip_ranges) => {
                            for idx in 0..ip_ranges.len() {
                                let range_i = &ip_ranges[idx];
                                for range_j in &ip_ranges[idx + 1..] {
                                    // Check for overlap
                                    let overlaps = match (
                                        ExplicitIpRange::from(range_i.clone()),
                                        ExplicitIpRange::from(range_j.clone()),
                                    ) {
                                        (ExplicitIpRange::V4(r_i), ExplicitIpRange::V4(r_j)) => {
                                            r_i.start() <= r_j.end() && r_j.start() <= r_i.end()
                                        }
                                        (ExplicitIpRange::V6(r_i), ExplicitIpRange::V6(r_j)) => {
                                            r_i.start() <= r_j.end() && r_j.start() <= r_i.end()
                                        }
                                        // Different IP versions cannot overlap
                                        _ => false,
                                    };

                                    if overlaps {
                                        let node_str =
                                            AstPrintVisitor::comparison_expr_to_string(node);
                                        let range_i_str = AstPrintVisitor::format_ip_range(range_i);
                                        let range_j_str = AstPrintVisitor::format_ip_range(range_j);

                                        self.result += &format!(
                                            "Found duplicate entry in list comparison: \
                                             {node_str}\nThe values `{range_i_str}` and \
                                             `{range_j_str}` overlap.\n",
                                        );
                                    }
                                }
                            }
                        }
                        wirefilter::RhsValues::Bytes(items) => {
                            for idx in 0..items.len() {
                                let item_i = &items[idx].data;
                                for item_j in &items[idx + 1..] {
                                    let item_j = &item_j.data;
                                    if item_i == item_j {
                                        let node_str =
                                            AstPrintVisitor::comparison_expr_to_string(node);
                                        let item_str = AstPrintVisitor::escape_bytes(item_i);

                                        self.result += &format!(
                                            "Found duplicate entry in list comparison: \
                                             {node_str}\nThe value `{item_str}` appears multiple \
                                             times in the list.\n"
                                        );
                                    }
                                }
                            }
                        }
                        // Unreachable branches due to uninhabited types
                        wirefilter::RhsValues::Array(..)
                        | wirefilter::RhsValues::Bool(..)
                        | wirefilter::RhsValues::Map(..) => unreachable!(),
                    }
                }

                self.visit_value_expr(&node.lhs);
            }
        }

        ast.walk(&mut visitor);
        visitor.result
    }
}

fn parse_expression(expr: &str) -> Result<String> {
    let linter = Linter::new();
    let mut ast = RULE_SCHEME.parse(expr).map_err(|err| anyhow!("{err}"))?;
    let result = linter.lint(&mut ast);
    Ok(result)

    // println!("Parsed filter representation: {ast:#?}",);
    // let mut visitor = ast_printer::AstPrintVisitor::new();
    // ast.walk(&mut visitor);
    // println!(
    //     "Assembled expression:\n{}\nOriginal expression:\n{}",
    //     visitor.into_string(), e
    // );

    // Ok(serde_json::to_string(&ast)?)
}

fn get_ast(expr: &str) -> Result<String> {
    let ast = RULE_SCHEME.parse(expr).map_err(|err| anyhow!("{err}"))?;
    Ok(format!("{ast:#?}"))
}

#[cfg(test)]
mod linter_tests {
    use super::*;
    use expect_test::{Expect, expect};

    #[track_caller]
    fn expect_lint_message(expr: &str, expected: Expect) {
        let linter = Linter::new();
        let mut ast = RULE_SCHEME
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        let msg = linter.lint(&mut ast);
        assert!(
            !msg.is_empty(),
            "Expected a lint message but received nothing."
        );
        expected.assert_eq(&msg);
    }

    #[track_caller]
    fn assert_no_lint_message(expr: &str) {
        let linter = Linter::new();
        let mut ast = RULE_SCHEME
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        let msg = linter.lint(&mut ast);
        assert!(
            msg.is_empty(),
            "Expected no lint message but received:\n{}",
            msg
        );
    }

    #[track_caller]
    fn assert_simplify_ast(expr: &str, expected: Expect) {
        let linter = Linter::new();
        let mut ast = RULE_SCHEME
            .parse(expr)
            .expect("All wirefilter rules in the test must be valid expressions.");
        linter.simplify_ast(&mut ast);
        expected.assert_debug_eq(&ast);
    }

    #[test]
    fn test_illogical_conditions_and() {
        expect_lint_message(
            r#"http.host eq "example.com" and http.host eq "example.org""#,
            expect![[r#"
                Found illogical condition: http.host eq "example.com" and http.host eq "example.org"
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
        expect_lint_message(
            r#"http.host eq "example.com" and http.host in { "example.org" }"#,
            expect![[r#"
                Found illogical condition: http.host eq "example.com" and http.host in {"example.org"}
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
        expect_lint_message(
            r#"http.host in { "example.com" } and http.host eq "example.org""#,
            expect![[r#"
                Found illogical condition: http.host in {"example.com"} and http.host eq "example.org"
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
    }

    #[test]
    fn test_illogical_conditions_and_parens() {
        expect_lint_message(
            r#"http.host eq "example.com" and (http.host eq "example.org")"#,
            expect![[r#"
                Found illogical condition: http.host eq "example.com" and http.host eq "example.org"
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
        expect_lint_message(
            r#"(http.host eq "example.com") and http.host in { "example.org" }"#,
            expect![[r#"
                Found illogical condition: http.host eq "example.com" and http.host in {"example.org"}
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
        expect_lint_message(
            r#"(http.host in { "example.com" }) and (http.host eq "example.org")"#,
            expect![[r#"
                Found illogical condition: http.host in {"example.com"} and http.host eq "example.org"
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
        expect_lint_message(
            r#"http.host eq "example.com" and (ip.src eq 1.2.3.4 and http.host eq "example.org")"#,
            expect![[r#"
                Found illogical condition: http.host eq "example.com" and ip.src eq 1.2.3.4 and http.host eq "example.org"
                The value `http.host` is compared for equality multiple times in an AND expression.
            "#]],
        );
    }

    #[test]
    fn test_illogical_conditions_or() {
        expect_lint_message(
            r#"http.host != "example.com" or http.host != "example.org""#,
            expect![[r#"
                Found illogical condition: http.host ne "example.com" or http.host ne "example.org"
                The value `http.host` is compared for not-equality multiple times in an OR expression.
            "#]],
        );
        expect_lint_message(
            r#"not http.host eq "example.com" or http.host != "example.org""#,
            expect![[r#"
                Found illogical condition: not http.host eq "example.com" or http.host ne "example.org"
                The value `http.host` is compared for not-equality multiple times in an OR expression.
            "#]],
        );
        expect_lint_message(
            r#"http.host != "example.com" or not http.host eq "example.org""#,
            expect![[r#"
                Found illogical condition: http.host ne "example.com" or not http.host eq "example.org"
                The value `http.host` is compared for not-equality multiple times in an OR expression.
            "#]],
        );
        expect_lint_message(
            r#"http.host != "example.com" or not http.host in { "example.org" }"#,
            expect![[r#"
                Found illogical condition: http.host ne "example.com" or not http.host in {"example.org"}
                The value `http.host` is compared for not-equality multiple times in an OR expression.
            "#]],
        );
        expect_lint_message(
            r#"not http.host in { "example.com" } or http.host ne "example.org""#,
            expect![[r#"
                Found illogical condition: not http.host in {"example.com"} or http.host ne "example.org"
                The value `http.host` is compared for not-equality multiple times in an OR expression.
            "#]],
        );
    }

    #[test]
    fn test_simplify_parens() {
        assert_simplify_ast(
            "ssl and (ssl)",
            expect![[r#"
            Combining {
                op: And,
                items: [
                    Comparison(
                        ComparisonExpr {
                            lhs: IndexExpr {
                                identifier: Field(
                                    ssl,
                                ),
                                indexes: [],
                            },
                            op: IsTrue,
                        },
                    ),
                    Comparison(
                        ComparisonExpr {
                            lhs: IndexExpr {
                                identifier: Field(
                                    ssl,
                                ),
                                indexes: [],
                            },
                            op: IsTrue,
                        },
                    ),
                ],
            }
        "#]],
        );
    }
    #[test]
    fn test_simplify_parens_levels() {
        assert_simplify_ast(
            "ssl and (ssl and ssl and (ssl and ssl and ssl and ssl))",
            expect![[r#"
                Combining {
                    op: And,
                    items: [
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                        Comparison(
                            ComparisonExpr {
                                lhs: IndexExpr {
                                    identifier: Field(
                                        ssl,
                                    ),
                                    indexes: [],
                                },
                                op: IsTrue,
                            },
                        ),
                    ],
                }
            "#]],
        );
    }

    #[test]
    fn test_ip_range_overlap() {
        expect_lint_message(
            r#"ip.src in {1.2.3.4 1.2.3.4}"#,
            expect![[r#"
                Found duplicate entry in list comparison: ip.src in {1.2.3.4 1.2.3.4}
                The values `1.2.3.4` and `1.2.3.4` overlap.
            "#]],
        );
        expect_lint_message(
            r#"ip.src in {1.2.3.4 1.0.0.0/8}"#,
            expect![[r#"
                Found duplicate entry in list comparison: ip.src in {1.2.3.4 1.0.0.0/8}
                The values `1.2.3.4` and `1.0.0.0/8` overlap.
            "#]],
        );
        expect_lint_message(
            r#"ip.src in {2000::/32 2000::/48}"#,
            expect![[r#"
                Found duplicate entry in list comparison: ip.src in {2000::/32 2000::/48}
                The values `2000::/32` and `2000::/48` overlap.
            "#]],
        );

        // Different IP versions do not overlap
        assert_no_lint_message(r#"ip.src in {1.2.3.4 2000::/16}"#);
    }

    #[test]
    fn test_bytes_overlap() {
        expect_lint_message(
            r#"http.host in {"example.com" "example.com"}"#,
            expect![[r#"
                Found duplicate entry in list comparison: http.host in {"example.com" "example.com"}
                The value `example.com` appears multiple times in the list.
            "#]],
        );
    }

    #[test]
    fn test_reserved_ip_space() {
        expect_lint_message(
            r#"ip.src eq 127.0.0.1"#,
            expect![[r#"
                Found usage of reserved IP range: ip.src eq 127.0.0.1
                The value `127.0.0.1` is within reserved address space.
            "#]],
        );
        expect_lint_message(
            r#"ip.src in {10.0.0.0/8 8.8.8.8}"#,
            expect![[r#"
                Found usage of reserved IP range: ip.src in {10.0.0.0/8 8.8.8.8}
                The value `10.0.0.0/8` is within reserved address space.
            "#]],
        );
        expect_lint_message(
            r#"ip.src in { fe80:0:0:1234::/96 }"#,
            expect![[r#"
                Found usage of reserved IP range: ip.src in {fe80:0:0:1234::/96}
                The value `fe80:0:0:1234::/96` is within reserved address space.
            "#]],
        );

        assert_no_lint_message(r#"ip.src eq 8.8.8.8"#);
    }

    #[test]
    fn test_simplify_negated_eq() {
        expect_lint_message(
            r#"not http.host eq "example.com""#,
            expect![[r#"
                Found negated comparison: not http.host eq "example.com"
                Consider simplifying to: http.host ne "example.com"
            "#]],
        );
    }

    #[test]
    fn test_simplify_negated_lt() {
        expect_lint_message(
            r#"not http.response.code lt 400"#,
            expect![[r#"
                Found negated comparison: not http.response.code lt 400
                Consider simplifying to: http.response.code ge 400
            "#]],
        );
    }

    #[test]
    fn test_simplify_negated_le() {
        expect_lint_message(
            r#"not http.response.code le 200"#,
            expect![[r#"
                Found negated comparison: not http.response.code le 200
                Consider simplifying to: http.response.code gt 200
            "#]],
        );
    }

    #[test]
    fn test_simplify_negated_gt() {
        expect_lint_message(
            r#"not tcp.port gt 1024"#,
            expect![[r#"
                Found negated comparison: not tcp.port gt 1024
                Consider simplifying to: tcp.port le 1024
            "#]],
        );
    }

    #[test]
    fn test_simplify_negated_ge() {
        expect_lint_message(
            r#"not tcp.port ge 80"#,
            expect![[r#"
                Found negated comparison: not tcp.port ge 80
                Consider simplifying to: tcp.port lt 80
            "#]],
        );
    }

    #[test]
    fn test_int_range_overlap() {
        expect_lint_message(
            r#"http.response.code in {400 300..499}"#,
            expect![[r#"
                Found duplicate entry in list comparison: http.response.code in {400 300..499}
                The values `400..400` and `300..499` overlap.
            "#]],
        );
        expect_lint_message(
            r#"http.response.code in {200..499 300..307}"#,
            expect![[r#"
            Found duplicate entry in list comparison: http.response.code in {200..499 300..307}
            The values `200..499` and `300..307` overlap.
        "#]],
        );

        assert_no_lint_message(r#"http.response.code in {200 201 202..204 205..207 208}"#);
    }
}
