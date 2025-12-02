use anyhow::{Result, anyhow};
use ipnet::IpNet;
use pyo3::prelude::*;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use wirefilter::{ComparisonExpr, ExecutionContext, FieldRef, Scheme, Type, ValueExpr, Visitor};

/// A Python module implemented in Rust.
#[pymodule]
mod cloudflare_rules {
    use pyo3::prelude::*;

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    fn parse_expression(e: &str) -> PyResult<String> {
        Ok(super::parse_expression(e)?)
    }
}

fn parse_expression(e: &str) -> Result<String> {
    // Create a map of possible filter fields.
    let scheme = Scheme! {
        http.method: Bytes,
        http.ua: Bytes,
        port: Int,
        req.srcip: Ip,
    }
    .build();
    // Parse a Wireshark-like expression into an AST.
    let ast = scheme.parse(e).map_err(|err| anyhow!("{err}"))?;

    println!("Parsed filter representation: {ast:#?}",);
    let mut visitor = AstPrintVisitor::new();
    ast.walk(&mut visitor);
    println!(
        "Assembled expression:\n{}\nOriginal expression:\n{}",
        visitor.0, e
    );

    Ok(serde_json::to_string(&ast)?)
}

struct AstPrintVisitor(String);

impl AstPrintVisitor {
    fn new() -> Self {
        AstPrintVisitor(String::new())
    }

    fn visit_int(&mut self, int: &i64) {
        self.0.push_str(&format!("{int}"));
    }

    fn visit_int_list(&mut self, ints: &[wirefilter::IntRange]) {
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
    }

    fn visit_regex(&mut self, regex: &wirefilter::Regex) {
        self.0.push('"');
        self.0.push_str(regex.as_str());
        self.0.push('"');
    }

    fn visit_bytes(&mut self, bytes: &wirefilter::Bytes) {
        self.0.push('"');
        bytes.as_ref().iter().for_each(|b| match b {
            b'\\' => self.0.push_str("\\\\"),
            b'"' => self.0.push_str("\\\""),
            b if b.is_ascii_graphic() => self.0.push(*b as char),
            b => self.0.push_str(&format!("\\x{:02x}", b)),
        });
        self.0.push('"');
    }

    fn visit_bytes_list(&mut self, bytes: &[wirefilter::Bytes]) {
        for (idx, bytes) in bytes.iter().enumerate() {
            if idx > 0 {
                self.0.push(' ');
            }
            self.visit_bytes(bytes);
        }
    }

    fn visit_ip_addr(&mut self, ip: &IpAddr) {
        self.0.push_str(&format!("{ip:?}"));
    }

    fn visit_ip_addr_list(&mut self, ips: &[wirefilter::IpRange]) {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum IpTypes {
            Single(IpAddr),
            Net(IpNet),
            Range { start: IpAddr, end: IpAddr },
        }

        for (idx, ip) in ips.iter().enumerate() {
            if idx > 0 {
                self.0.push(' ');
            }
            let ip: IpTypes = serde_json::from_str(&serde_json::to_string(&ip).unwrap()).unwrap();
            match ip {
                IpTypes::Single(ip_addr) => self.0.push_str(&ip_addr.to_string()),
                IpTypes::Net(ip_net) => self.0.push_str(&ip_net.to_string()),
                IpTypes::Range { start, end } => {
                    if start == end {
                        self.0.push_str(&start.to_string());
                    } else {
                        self.0.push_str(&format!("{}..{}", start, end));
                    }
                }
            }
        }
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
                self.visit_comparison_expr(comparison_expr)
            }
            wirefilter::LogicalExpr::Parenthesized(parenthesized_expr) => {
                println!("Visit parenthesized expr {parenthesized_expr:?}");
                self.0.push('(');
                self.visit_logical_expr(&parenthesized_expr.expr);
                self.0.push(')');
            }
            wirefilter::LogicalExpr::Unary { op, arg } => todo!(),
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
                    wirefilter::RhsValue::Bool(uninhabited_bool) => self.0.push_str("Bool(...)"),
                    wirefilter::RhsValue::Int(int) => self.visit_int(int),
                    wirefilter::RhsValue::Ip(ip_addr) => self.visit_ip_addr(ip_addr),
                    wirefilter::RhsValue::Bytes(bytes) => self.visit_bytes(bytes),
                    wirefilter::RhsValue::Array(uninhabited_array) => self.0.push_str("Array(...)"),
                    wirefilter::RhsValue::Map(uninhabited_map) => self.0.push_str("Map(...)"),
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
                self.0.push_str(" in {");
                match rhs_values {
                    wirefilter::RhsValues::Bool(uninhabited_bool) => self.0.push_str("Bool(...)"),
                    wirefilter::RhsValues::Int(ints) => self.visit_int_list(ints),
                    wirefilter::RhsValues::Ip(ip_addrs) => self.visit_ip_addr_list(ip_addrs),
                    wirefilter::RhsValues::Bytes(bytes) => self.visit_bytes_list(bytes),
                    wirefilter::RhsValues::Array(uninhabited_array) => {
                        self.0.push_str("Array(...)")
                    }
                    wirefilter::RhsValues::Map(uninhabited_map) => self.0.push_str("Map(...)"),
                }
                self.0.push('}');
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
