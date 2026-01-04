//! Read TF files and runs the linter on all "expression" attributes

use annotate_snippets::{AnnotationKind, Group, Snippet};
use anyhow::{Context, Result};
use cloudflare_rules::LinterConfig;
use hcl_edit::structure::Body;
use hcl_edit::visit::Visit;
use hcl_edit::{Decorate, Span};
use log::{debug, warn};
use std::ops::Range;

#[derive(clap::Parser, Debug)]
#[command(arg_required_else_help(true))]
struct CliArgs {
    #[arg(short = 'c', long = "config")]
    config: Option<String>,
    // #[arg(short = 'f', long = "file")]
    files: Vec<String>,
}

/// Visitor for TF files
struct ExpressionVisitor<'a> {
    file: &'a str,
    input: &'a str,
    config: &'a LinterConfig,
    groups: Vec<Group<'a>>,
    /// Keep track of the surrounding block
    block_span: Vec<Range<usize>>,
}

impl Visit for ExpressionVisitor<'_> {
    fn visit_attr(&mut self, node: &hcl_edit::structure::Attribute) {
        if node.key.as_str() == "expression" {
            let mut config = self.config.clone();
            // Tune config if comment-command is found
            for line in node
                .decor()
                .prefix()
                .map(|rs| &**rs)
                .unwrap_or("")
                .lines()
                .filter(|line| line.contains("cfrl:"))
            {
                // Extract the part after "cfrl:"
                if let Some(cfg) = line.rsplit("cfrl:").next()
                    && let Err(err) = config.parse_expr_config(cfg)
                {
                    warn!(
                        "Cannot parse cfrl config string. Using default config.\n{err}\nFound in \
                         line: {line}"
                    );
                    config = self.config.clone();
                }
            }

            let rule_expr = node.value.as_str().unwrap_or("");
            let lint_result =
                cloudflare_rules::parse_and_lint_expression_with_config(config, rule_expr);
            for report in lint_result {
                let mut group = if report.id == "parse_error" {
                    annotate_snippets::Level::ERROR
                } else {
                    annotate_snippets::Level::WARNING
                }
                .primary_title(report.title)
                .id(report.id);
                if let Some(url) = report.url {
                    group = group.id_url(url);
                }

                let annotation = {
                    let span = match report.span {
                        cloudflare_rules::Span::Missing => node.value.span().unwrap(),
                        cloudflare_rules::Span::Byte(span) => {
                            let string_lit_span = node.value.span().unwrap();
                            convert_internal_byterange_to_global(self.input, string_lit_span, span)
                        }
                        cloudflare_rules::Span::ReverseByte(reverse_span) => {
                            let span = (rule_expr.len() - reverse_span.start)
                                ..(rule_expr.len() - reverse_span.end);
                            let string_lit_span = node.value.span().unwrap();
                            convert_internal_byterange_to_global(self.input, string_lit_span, span)
                        }
                    };
                    AnnotationKind::Primary.span(span).label(report.message)
                };
                let mut annotation = Snippet::source(self.input)
                    .path(self.file)
                    .annotation(annotation);
                if let Some(block_span) = self.block_span.last() {
                    annotation =
                        annotation.annotation(AnnotationKind::Visible.span(block_span.clone()));
                }
                let group = group.element(annotation);
                self.groups.push(group);
            }
            self.visit_ident(&node.key);
            self.visit_expr(&node.value);
        }
    }

    fn visit_block(&mut self, node: &hcl_edit::structure::Block) {
        let span = node.ident.span();
        if let Some(span) = &span {
            self.block_span.push(span.clone());
        }
        hcl_edit::visit::visit_block(self, node);
        if !self.block_span.is_empty() && span.is_some() {
            self.block_span.pop();
        }
    }
}

/// Convert from the byte ranges inside an expression to a global range inside the file
///
/// The ranges returned by the linter are relative to the expression string given.
/// This differs from the file ranges, by being offset from the start, and for having escape sequences.
/// This takes the global range of the expression string and the internal range and creates a new global range that covers the subpart of the internal range.
/// It does this while taking care of escape sequences that where one internal byte might map to multiple global bytes.
fn convert_internal_byterange_to_global(
    input: &str,
    global: Range<usize>,
    internal: Range<usize>,
) -> Range<usize> {
    // Get the string snippet referred by the global range
    let Some(rawstring) = input.get(global.clone()) else {
        return global;
    };

    let mut inner_byte_count: usize = 0;
    let mut global_start = 0;
    let mut global_end = 0;
    let mut escaped = false;
    let mut char_indices = rawstring.char_indices();
    // Skip the opening "
    char_indices.next();
    while let Some((mut idx, c)) = char_indices.next() {
        if inner_byte_count == internal.start {
            global_start = global.start + idx;
        }

        match c {
            '\\' if !escaped => escaped = true,
            'n' | 'r' | 't' | '\\' | '"' | '/' | 'b' | 'f' if escaped => {
                inner_byte_count += 1;
                escaped = false;
            }
            'u' if escaped => {
                let mut hexbuf = String::new();
                for _ in 0..4 {
                    if let Some((i, c)) = char_indices.next() {
                        idx = i;
                        hexbuf.push(c);
                    }
                }
                let decoded_u32 = u32::from_str_radix(&hexbuf, 16).expect("Invalid hex");
                let c = char::from_u32(decoded_u32).expect("Invalid unicode point");
                inner_byte_count += c.len_utf8();
                escaped = false;
            }
            'U' if escaped => {
                let mut hexbuf = String::new();
                for _ in 0..8 {
                    if let Some((i, c)) = char_indices.next() {
                        idx = i;
                        hexbuf.push(c);
                    }
                }
                let decoded_u32 = u32::from_str_radix(&hexbuf, 16).expect("Invalid hex");
                let c = char::from_u32(decoded_u32).expect("Invalid unicode point");
                inner_byte_count += c.len_utf8();
                escaped = false;
            }
            c => inner_byte_count += c.len_utf8(),
        }

        if inner_byte_count == internal.end {
            global_end = global.start + idx + c.len_utf8();
        }
    }

    if global_start != 0 && global_end != 0 {
        global_start..global_end
    } else {
        global
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let cli_args: CliArgs = clap::Parser::parse();

    let config: LinterConfig = match cli_args.config {
        Some(file) => {
            let data = std::fs::read_to_string(&file)
                .context(format!("Cannot read config file at {file}"))?;
            toml::from_str(&data).context(format!("Cannot parse config file at {file}"))?
        }
        None => LinterConfig::default(),
    };

    for file in cli_args.files {
        debug!("Process file {file}");
        let input =
            std::fs::read_to_string(&file).context(format!("Could not read file: {file}"))?;
        let body = input
            .parse::<Body>()
            .context(format!("Failed for parse Terraform file {file}"))?;

        let mut visitor = ExpressionVisitor {
            file: &file,
            input: &input,
            config: &config,
            groups: Vec::new(),
            block_span: Vec::new(),
        };
        visitor.visit_body(&body);

        let renderer = annotate_snippets::Renderer::styled()
            .decor_style(annotate_snippets::renderer::DecorStyle::Unicode);
        println!("{}", renderer.render(&visitor.groups));
    }

    Ok(())
}
