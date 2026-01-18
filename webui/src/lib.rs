//! Web UI for Cloudflare Rules Language Linter
//!
//! This crate provides a WebAssembly-based user interface for linting
//! Cloudflare Rules Language expressions. It leverages the `cloudflare_rules`
//! crate for parsing and linting, and uses `annotate_snippets` for rendering
//! lint messages in a user-friendly format.

use wasm_bindgen::prelude::*;
use web_sys::{Event, HtmlTextAreaElement};

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    // #[wasm_bindgen(js_namespace = console)]
    // fn log(s: &str);
}

#[wasm_bindgen(start)]
fn run() -> Result<(), JsValue> {
    set_panic_hook();

    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let input = document
        .get_element_by_id("cloudflare-rules-input")
        .expect("Input element must exist");
    let output = document
        .get_element_by_id("cloudflare-rules-output")
        .expect("Output element must exist");

    #[allow(trivial_casts)]
    let cb = Closure::wrap(Box::new(move |e: Event| {
        let input = e
            .current_target()
            .unwrap()
            .dyn_into::<HtmlTextAreaElement>()
            .unwrap();

        let rule_expr = input.value();
        // log(&format!("{rule_expr:?}"));
        // Reset to empty if nothing is entered
        if rule_expr.trim().is_empty() {
            output.set_inner_html("");
            output.set_class_name("");
            return;
        }

        let msg = cloudflare_rules::parse_and_lint_expression(&rule_expr);
        let mut has_error = false;
        let report: Vec<annotate_snippets::Group<'_>> = msg
            .into_iter()
            .map(|lint| {
                let mut group = if lint.id == "parse_error" {
                    has_error = true;
                    annotate_snippets::Level::ERROR
                } else {
                    annotate_snippets::Level::WARNING
                }
                .primary_title(lint.title)
                .id(lint.id);
                if let Some(url) = lint.url {
                    group = group.id_url(url);
                }
                group.element(annotate_snippets::Snippet::source(&rule_expr).annotation({
                    let span = match lint.span {
                        cloudflare_rules::Span::Missing => 0..rule_expr.len(),
                        cloudflare_rules::Span::Byte(span) => span,
                        cloudflare_rules::Span::ReverseByte(reverse_span) => {
                            (rule_expr.len() - reverse_span.start)
                                ..(rule_expr.len() - reverse_span.end)
                        }
                    };
                    annotate_snippets::AnnotationKind::Primary
                        .span(span)
                        .label(lint.message)
                }))
            })
            .collect();
        let renderer = annotate_snippets::Renderer::styled()
            .decor_style(annotate_snippets::renderer::DecorStyle::Unicode);

        let (output_msg, class) = if report.is_empty() {
            ("No issues found :)".to_string(), "alert alert-success")
        } else {
            (
                ansi_to_html::convert(&renderer.render(&report).to_string()).unwrap(),
                if has_error {
                    "alert alert-danger"
                } else {
                    "alert alert-warning"
                },
            )
        };

        output.set_inner_html(&output_msg);
        output.set_class_name(class);
    }) as Box<dyn FnMut(_)>);

    input.add_event_listener_with_callback("input", cb.as_ref().unchecked_ref())?;
    cb.forget();

    // Trigger a run of the callback on load
    input.dispatch_event(&Event::new("input").unwrap()).unwrap();

    Ok(())
}

fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}
