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
            b if *b == 0x20 || b.is_ascii_graphic() => escaped.push(*b as char),
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
        // Count consecutive # in string
        let regex_literal = regex.as_str();
        // Count the current run of #s and the longest run of #s
        let (_, hash_count): (u32, u32) = regex_literal.chars().fold((0, 0), |(curr, max), c| {
            if c == '#' {
                (curr + 1, max.max(curr + 1))
            } else {
                (0, max)
            }
        });
        self.0.push('r');
        // Print 1 more than hash_count
        for _ in 0..=hash_count {
            self.0.push('#');
        }
        self.0.push('"');
        self.0.push_str(regex.as_str());
        self.0.push('"');
        for _ in 0..=hash_count {
            self.0.push('#');
        }
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

    fn visit_rhs_value(&mut self, rhs: &wirefilter::RhsValue) {
        match rhs {
            wirefilter::RhsValue::Bool(_uninhabited_bool) => unreachable!(),
            wirefilter::RhsValue::Int(int) => self.visit_int(int),
            wirefilter::RhsValue::Ip(ip_addr) => self.visit_ip_addr(ip_addr),
            wirefilter::RhsValue::Bytes(bytes) => self.visit_bytes(bytes),
            wirefilter::RhsValue::Array(_uninhabited_array) => unreachable!(),
            wirefilter::RhsValue::Map(_uninhabited_map) => unreachable!(),
        }
    }
}

impl<'a> Visitor<'a> for AstPrintVisitor {
    fn visit_expr(&mut self, node: &'a impl wirefilter::Expr) {
        node.walk(self)
    }

    fn visit_logical_expr(&mut self, node: &'a wirefilter::LogicalExpr) {
        match node {
            wirefilter::LogicalExpr::Combining { op, items, .. } => {
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
                self.visit_comparison_expr(comparison_expr)
            }
            wirefilter::LogicalExpr::Parenthesized(parenthesized_expr) => {
                self.0.push('(');
                self.visit_logical_expr(&parenthesized_expr.expr);
                self.0.push(')');
            }
            wirefilter::LogicalExpr::Unary { op, arg, .. } => {
                match op {
                    wirefilter::UnaryOp::Not => self.0.push_str("not "),
                }
                self.visit_logical_expr(arg);
            }
        }
    }

    fn visit_comparison_expr(&mut self, node: &'a wirefilter::ComparisonExpr) {
        self.visit_index_expr(&node.lhs);
        match &node.op {
            wirefilter::ComparisonOpExpr::IsTrue => {
                // No additional action needed
                // The lhs is already a boolean value
            }
            wirefilter::ComparisonOpExpr::Ordering { op, rhs } => {
                match op {
                    wirefilter::OrderingOp::Equal => self.0.push_str(" eq "),
                    wirefilter::OrderingOp::NotEqual => self.0.push_str(" ne "),
                    wirefilter::OrderingOp::GreaterThanEqual => self.0.push_str(" ge "),
                    wirefilter::OrderingOp::LessThanEqual => self.0.push_str(" le "),
                    wirefilter::OrderingOp::GreaterThan => self.0.push_str(" gt "),
                    wirefilter::OrderingOp::LessThan => self.0.push_str(" lt "),
                }
                self.visit_rhs_value(rhs);
            }
            wirefilter::ComparisonOpExpr::Int { op, rhs } => {
                match op {
                    wirefilter::IntOp::BitwiseAnd => self.0.push_str(" & "),
                }
                self.0.push_str(&rhs.to_string());
            }
            wirefilter::ComparisonOpExpr::Contains(bytes) => {
                self.0.push_str(" contains ");
                self.visit_bytes(bytes);
            }
            wirefilter::ComparisonOpExpr::Matches(regex) => {
                self.0.push_str(" matches ");
                self.visit_regex(regex);
            }
            wirefilter::ComparisonOpExpr::Wildcard(wildcard) => {
                self.0.push_str(&format!(" wildcard {:?}", wildcard));
            }
            wirefilter::ComparisonOpExpr::StrictWildcard(wildcard) => {
                self.0.push_str(&format!(" strict wildcard {:?}", wildcard));
            }
            wirefilter::ComparisonOpExpr::OneOf(rhs_values) => {
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
            wirefilter::ComparisonOpExpr::ContainsOneOf(_items) => {
                unreachable!("Syntax feature not supported")
            }
            wirefilter::ComparisonOpExpr::InList { name, .. } => {
                self.0.push_str(" in ");
                self.0.push('$');
                self.0.push_str(name.as_str());
            }
        }
    }

    fn visit_value_expr(&mut self, node: &'a impl wirefilter::ValueExpr) {
        node.walk(self)
    }

    fn visit_index_expr(&mut self, node: &'a wirefilter::IndexExpr) {
        self.visit_value_expr(node);
        for index in &node.indexes {
            match index {
                wirefilter::FieldIndex::ArrayIndex(i) => {
                    self.0.push('[');
                    self.0.push_str(&i.to_string());
                    self.0.push(']');
                }
                wirefilter::FieldIndex::MapKey(s) => {
                    self.0.push_str("[\"");
                    self.0.push_str(s);
                    self.0.push_str("\"]");
                }
                wirefilter::FieldIndex::MapEach => {
                    self.0.push_str("[*]");
                }
            }
        }
    }

    fn visit_function_call_expr(&mut self, node: &'a wirefilter::FunctionCallExpr) {
        struct FunctionCallVisitor<'a> {
            inner: &'a mut AstPrintVisitor,
            buffer: String,
        }

        impl<'a> Visitor<'a> for FunctionCallVisitor<'a> {
            fn visit_function(&mut self, func: &'a wirefilter::Function) {
                self.inner.0.push_str(func.name());
                self.inner.0.push('(');
                self.inner.0.push_str(&self.buffer);
                self.inner.0.push(')');
            }

            fn visit_function_call_arg_expr(&mut self, node: &'a wirefilter::FunctionCallArgExpr) {
                if !self.buffer.is_empty() {
                    self.buffer.push_str(", ");
                }
                // TODO: can this be done without allocating a new AstPrintVisitor?
                let mut arg_visitor = AstPrintVisitor::new();
                match node {
                    wirefilter::FunctionCallArgExpr::IndexExpr(index_expr) => {
                        arg_visitor.visit_index_expr(index_expr)
                    }
                    wirefilter::FunctionCallArgExpr::Literal(lit) => {
                        arg_visitor.visit_rhs_value(lit)
                    }
                    wirefilter::FunctionCallArgExpr::Logical(logical_expr) => {
                        arg_visitor.visit_logical_expr(logical_expr)
                    }
                }
                self.buffer.push_str(&arg_visitor.into_string());
            }
        }

        node.walk(&mut FunctionCallVisitor {
            inner: self,
            buffer: String::new(),
        });
    }

    fn visit_function_call_arg_expr(&mut self, _node: &'a wirefilter::FunctionCallArgExpr) {
        unreachable!("Function visited outside of FunctionCallExpr");
    }

    fn visit_field(&mut self, field: &'a wirefilter::Field) {
        self.0.push_str(field.name());
    }

    fn visit_function(&mut self, _func: &'a wirefilter::Function) {
        unreachable!("Function visited outside of FunctionCallExpr");
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

    #[test]
    fn test_roundtrip_function() {
        ensure_roundtrip_parse_print(r#"lower(http.host) eq """#);
    }

    #[test]
    fn test_roundtrip_function_multiple_args() {
        ensure_roundtrip_parse_print(r#"cidr(ip.src, 24, 24) eq 113.10.0.0"#);
    }

    #[test]
    fn test_roundtrip_indexing() {
        ensure_roundtrip_parse_print(r#"http.request.headers["content-type"][0] eq """#);
    }

    #[test]
    fn test_roundtrip_function_and_indexing() {
        ensure_roundtrip_parse_print(
            r#"any(http.request.headers["content-type"][*] eq "application/json")"#,
        );
    }

    #[test]
    fn test_roundtrip_list() {
        ensure_roundtrip_parse_print(r#"ip.src in $always"#);
    }
}

#[cfg(test)]
mod test_fuzz_results {
    use super::*;
    use pretty_assertions::assert_eq;

    #[track_caller]
    pub fn ensure_roundtrip_print_parse(expression: &str) {
        let schema = crate::scheme::build_scheme();
        let ast_original = schema
            .parse(expression)
            .expect("Failed to parse expression");
        let mut visitor = AstPrintVisitor::new();
        ast_original.walk(&mut visitor);
        dbg!(&ast_original.expression());
        let printed_expression = visitor.into_string();
        dbg!(&printed_expression);

        let ast_reparsed = schema
            .parse(&printed_expression)
            .expect("Failed to parse re-printed expression");
        assert_eq!(ast_original.expression(), ast_reparsed.expression());
    }

    #[test]
    fn test_fuzz_00001() {
        // Test the printing of regex with escaped quotes
        ensure_roundtrip_print_parse(r#"http.request.uri.path  matches"_  \" ""#);
    }

    #[test]
    fn test_fuzz_00002() {
        // Test the printing of regex with escaped quotes
        ensure_roundtrip_print_parse(
            r#"http.request.uri matches"
c.""#,
        );
    }

    #[test]
    fn test_fuzz_00003() {
        // Test the printing of regex with "# sequences in the string
        ensure_roundtrip_print_parse(r##"http.request.uri.path     matches" [     "#!!] ""##);
    }
}
