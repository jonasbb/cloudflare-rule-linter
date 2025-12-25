use std::net::IpAddr;
use std::ops::RangeInclusive;
use wirefilter::{ValueExpr, Visitor};

pub struct AstPrintVisitor(String);

impl AstPrintVisitor {
    pub fn new() -> Self {
        AstPrintVisitor(String::new())
    }

    pub fn ast_to_string(ast: &wirefilter::FilterAst) -> String {
        let mut visitor = AstPrintVisitor::new();
        ast.walk(&mut visitor);
        visitor.into_string()
    }

    pub fn logical_expr_to_string(expr: &wirefilter::LogicalExpr) -> String {
        let mut visitor = AstPrintVisitor::new();
        visitor.visit_logical_expr(expr);
        visitor.into_string()
    }

    pub fn comparison_expr_to_string(expr: &wirefilter::ComparisonExpr) -> String {
        let mut visitor = AstPrintVisitor::new();
        visitor.visit_comparison_expr(expr);
        visitor.into_string()
    }

    pub fn value_expr_to_string(expr: &impl ValueExpr) -> String {
        let mut visitor = AstPrintVisitor::new();
        expr.walk(&mut visitor);
        visitor.into_string()
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn escape_bytes(bytes: &[u8]) -> String {
        let mut escaped = String::with_capacity(bytes.len());
        bytes.iter().for_each(|b| match b {
            b'\\' => escaped.push_str("\\\\"),
            b'"' => escaped.push_str("\\\""),
            b if b.is_ascii_graphic() => escaped.push(*b as char),
            b => escaped.push_str(&format!("\\x{:02x}", b)),
        });
        escaped
    }

    pub fn format_ip_range(ip: &wirefilter::IpRange) -> String {
        match ip {
            wirefilter::IpRange::Explicit(explicit_ip_range) => match explicit_ip_range {
                wirefilter::ExplicitIpRange::V4(range_inclusive) => {
                    if range_inclusive.start() == range_inclusive.end() {
                        format!("{}", range_inclusive.start())
                    } else {
                        format!("{}..{}", range_inclusive.start(), range_inclusive.end())
                    }
                }
                wirefilter::ExplicitIpRange::V6(range_inclusive) => {
                    if range_inclusive.start() == range_inclusive.end() {
                        format!("{}", range_inclusive.start())
                    } else {
                        format!("{}..{}", range_inclusive.start(), range_inclusive.end())
                    }
                }
            },
            wirefilter::IpRange::Cidr(ip_cidr) => match ip_cidr {
                wirefilter::IpCidr::V4(ipv4_cidr) => ipv4_cidr.to_string(),
                wirefilter::IpCidr::V6(ipv6_cidr) => ipv6_cidr.to_string(),
            },
        }
    }

    fn visit_int(&mut self, int: &i64) {
        self.0.push_str(&format!("{int}"));
    }

    fn visit_int_list(&mut self, ints: &[wirefilter::IntRange]) {
        self.0.push('{');
        for (idx, int) in ints.iter().enumerate() {
            if idx > 0 {
                self.0.push(' ');
            }
            let range = RangeInclusive::from(int);
            if range.start() == range.end() {
                self.0.push_str(&format!("{}", range.start()));
            } else {
                self.0
                    .push_str(&format!("{}..{}", range.start(), range.end()));
            }
        }
        self.0.push('}');
    }

    fn visit_regex(&mut self, regex: &wirefilter::Regex) {
        self.0.push('"');
        self.0.push_str(regex.as_str());
        self.0.push('"');
    }

    fn visit_bytes(&mut self, bytes: &wirefilter::Bytes) {
        self.0.push('"');
        self.0.push_str(&AstPrintVisitor::escape_bytes(bytes));
        self.0.push('"');
    }

    fn visit_bytes_list(&mut self, bytes: &[wirefilter::Bytes]) {
        self.0.push('{');
        for (idx, bytes) in bytes.iter().enumerate() {
            if idx > 0 {
                self.0.push(' ');
            }
            self.visit_bytes(bytes);
        }
        self.0.push('}');
    }

    fn visit_ip_addr(&mut self, ip: &IpAddr) {
        self.0.push_str(&format!("{ip:?}"));
    }

    fn visit_ip_addr_list(&mut self, ips: &[wirefilter::IpRange]) {
        self.0.push('{');
        for (idx, ip) in ips.iter().enumerate() {
            if idx > 0 {
                self.0.push(' ');
            }
            let ip = AstPrintVisitor::format_ip_range(ip);
            self.0.push_str(&ip);
        }
        self.0.push('}');
    }
}

impl<'a> Visitor<'a> for AstPrintVisitor {
    fn visit_expr(&mut self, node: &'a impl wirefilter::Expr) {
        println!("Visit expr {node:?}");
        node.walk(self)
    }

    fn visit_logical_expr(&mut self, node: &'a wirefilter::LogicalExpr) {
        println!("Visit logical expr {node:?}");
        match node {
            wirefilter::LogicalExpr::Combining { op, items } => {
                println!("Visit combining op {op:?} with items {items:?}");
                let op_str = match op {
                    wirefilter::LogicalOp::Or => " or ",
                    wirefilter::LogicalOp::Xor => " xor ",
                    wirefilter::LogicalOp::And => " and ",
                };
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        self.0.push_str(op_str);
                    }
                    self.visit_logical_expr(item);
                }
            }
            wirefilter::LogicalExpr::Comparison(comparison_expr) => {
                println!("Visit comparison expr {comparison_expr:?}");
                self.visit_comparison_expr(comparison_expr)
            }
            wirefilter::LogicalExpr::Parenthesized(parenthesized_expr) => {
                println!("Visit parenthesized expr {parenthesized_expr:?}");
                self.0.push('(');
                self.visit_logical_expr(&parenthesized_expr.expr);
                self.0.push(')');
            }
            wirefilter::LogicalExpr::Unary { op, arg } => {
                println!("Visit unary expr {op:?} with arg {arg:?}");
                match op {
                    wirefilter::UnaryOp::Not => self.0.push_str("not "),
                }
                self.visit_logical_expr(arg);
            }
        }
    }

    fn visit_comparison_expr(&mut self, node: &'a wirefilter::ComparisonExpr) {
        println!("Visit comparison expr {node:?}");
        node.lhs.walk(self);
        match &node.op {
            wirefilter::ComparisonOpExpr::IsTrue => {
                // No additional action needed
                // The lhs is already a boolean value
            }
            wirefilter::ComparisonOpExpr::Ordering { op, rhs } => {
                println!("Visit ordering op {op:?} with rhs {rhs:?}");
                match op {
                    wirefilter::OrderingOp::Equal => self.0.push_str(" eq "),
                    wirefilter::OrderingOp::NotEqual => self.0.push_str(" ne "),
                    wirefilter::OrderingOp::GreaterThanEqual => self.0.push_str(" ge "),
                    wirefilter::OrderingOp::LessThanEqual => self.0.push_str(" le "),
                    wirefilter::OrderingOp::GreaterThan => self.0.push_str(" gt "),
                    wirefilter::OrderingOp::LessThan => self.0.push_str(" lt "),
                }
                match rhs {
                    wirefilter::RhsValue::Bool(_uninhabited_bool) => unreachable!(),
                    wirefilter::RhsValue::Int(int) => self.visit_int(int),
                    wirefilter::RhsValue::Ip(ip_addr) => self.visit_ip_addr(ip_addr),
                    wirefilter::RhsValue::Bytes(bytes) => self.visit_bytes(bytes),
                    wirefilter::RhsValue::Array(_uninhabited_array) => unreachable!(),
                    wirefilter::RhsValue::Map(_uninhabited_map) => unreachable!(),
                }
            }
            wirefilter::ComparisonOpExpr::Int { op, rhs } => {
                println!("Visit int op {op:?} with rhs {rhs:?}");
                match op {
                    wirefilter::IntOp::BitwiseAnd => self.0.push_str(" & "),
                }
                self.0.push_str(&rhs.to_string());
            }
            wirefilter::ComparisonOpExpr::Contains(bytes) => {
                println!("Visit contains with bytes {bytes:?}");
                self.0.push_str(" contains ");
                self.visit_bytes(bytes);
            }
            wirefilter::ComparisonOpExpr::Matches(regex) => {
                println!("Visit matches with regex {regex:?}");
                self.0.push_str(" matches ");
                self.visit_regex(regex);
            }
            wirefilter::ComparisonOpExpr::Wildcard(wildcard) => {
                println!("Visit wildcard with pattern {wildcard:?}");
                self.0.push_str(&format!(" wildcard {:?}", wildcard));
            }
            wirefilter::ComparisonOpExpr::StrictWildcard(wildcard) => {
                println!("Visit strict wildcard with pattern {wildcard:?}");
                self.0.push_str(&format!(" strict wildcard {:?}", wildcard));
            }
            wirefilter::ComparisonOpExpr::OneOf(rhs_values) => {
                println!("Visit one of with rhs values {rhs_values:?}");
                self.0.push_str(" in ");
                match rhs_values {
                    wirefilter::RhsValues::Bool(_uninhabited_bool) => unreachable!(),
                    wirefilter::RhsValues::Int(ints) => self.visit_int_list(ints),
                    wirefilter::RhsValues::Ip(ip_addrs) => self.visit_ip_addr_list(ip_addrs),
                    wirefilter::RhsValues::Bytes(bytes) => self.visit_bytes_list(bytes),
                    wirefilter::RhsValues::Array(_uninhabited_array) => unreachable!(),
                    wirefilter::RhsValues::Map(_uninhabited_map) => unreachable!(),
                }
            }
            wirefilter::ComparisonOpExpr::ContainsOneOf(items) => todo!(),
            wirefilter::ComparisonOpExpr::InList { list, name } => todo!(),
        }
    }

    fn visit_value_expr(&mut self, node: &'a impl wirefilter::ValueExpr) {
        println!("Visit value expr {node:?}");
        node.walk(self)
    }

    fn visit_index_expr(&mut self, node: &'a wirefilter::IndexExpr) {
        println!("Visit index expr {node:?}");
        self.visit_value_expr(node)
    }

    fn visit_function_call_expr(&mut self, node: &'a wirefilter::FunctionCallExpr) {
        println!("Visit function call expr {node:?}");
        self.visit_value_expr(node)
    }

    fn visit_function_call_arg_expr(&mut self, node: &'a wirefilter::FunctionCallArgExpr) {
        println!("Visit function call arg expr {node:?}");
        self.visit_value_expr(node)
    }

    fn visit_field(&mut self, field: &'a wirefilter::Field) {
        println!("Visit field {field:?}");
        self.0.push_str(field.name());
    }

    fn visit_function(&mut self, func: &'a wirefilter::Function) {
        println!("Visit function {func:?}");
        self.0.push_str("Function ");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[track_caller]
    pub fn ensure_roundtrip_parse_print(expression: &str) {
        let schema = crate::scheme::build_scheme();
        let ast = schema
            .parse(expression)
            .expect("Failed to parse expression");
        let mut visitor = AstPrintVisitor::new();
        ast.walk(&mut visitor);
        let printed_expression = visitor.into_string();
        assert_eq!(
            expression, printed_expression,
            "Roundtrip parse and print did not match"
        );
    }

    #[test]
    fn test_roundtrip_parse_print() {
        ensure_roundtrip_parse_print(r#"http.host eq "example.org""#);
        ensure_roundtrip_parse_print(r"ssl or ssl");
        ensure_roundtrip_parse_print(r"ssl and ssl");
    }

    #[test]
    fn test_roundtrip_parse_print_parentheses() {
        ensure_roundtrip_parse_print(r#"http.host ne "example.com" or http.host ne "example.org""#);
    }
}
