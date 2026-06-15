//! Web UI for Cloudflare Rules Language Linter
//!
//! This crate provides a WebAssembly-based user interface for linting
//! Cloudflare Rules Language expressions. It leverages the `cloudflare_rules`
//! crate for parsing and linting, and uses `annotate_snippets` for rendering
//! lint messages in a user-friendly format.

use wasm_bindgen::prelude::*;
use web_sys::{Event, HtmlSelectElement, HtmlTextAreaElement};

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    // #[wasm_bindgen(js_namespace = console)]
    // fn log(s: &str);
}

#[wasm_bindgen(start)]
fn run() -> Result<(), JsValue> {
    set_panic_hook();

    let window = web_sys::window().ok_or("no global `window` exists")?;
    let document = window
        .document()
        .ok_or("should have a document on window")?;
    let input = document
        .get_element_by_id("cloudflare-rules-input")
        .ok_or("Input element must exist")?;
    let phase = document
        .get_element_by_id("cloudflare-rules-phase")
        .ok_or("Phase element must exist")?;
    let output = document
        .get_element_by_id("cloudflare-rules-output")
        .ok_or("Output element must exist")?;

    #[allow(trivial_casts)]
    let cb = Closure::wrap(Box::new({
        let input = input.clone();
        let phase = phase.clone();

        move |_e: Event| {
            let input = input.clone().dyn_into::<HtmlTextAreaElement>().unwrap();

            let rule_expr = input.value();
            // Reset to empty if nothing is entered
            if rule_expr.trim().is_empty() {
                output.set_inner_html("");
                output.set_class_name("");
                return;
            }

            let mut has_error = false;

            let phase = phase.clone().dyn_into::<HtmlSelectElement>().unwrap();
            let phase = match cloudflare_rules::phase_name_to_phase(&phase.value()) {
                Some(phase) => phase,
                None => {
                    output.set_inner_html("");
                    output.set_text_content(Some(&format!(
                        "Cannot convert phase name `{}` into a phase.\n{:#?}\n{:?}",
                        phase.value(),
                        <cloudflare_rules::Phase as std::str::FromStr>::from_str(&phase.value()),
                        cloudflare_rules::phase_iter().next().unwrap().to_string()
                    )));
                    output.set_class_name("alert alert-danger");
                    return;
                }
            };

            let msg = cloudflare_rules::parse_and_lint_expression_with_config_and_phase(
                cloudflare_rules::LinterConfig::default(),
                &rule_expr,
                phase,
            );
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
                    {
                        // Strip out the hyperlink escape codes that annotate_snippets adds, since they don't work in this context and just add noise
                        let mut errors = renderer.render(&report).to_string();
                        while let Some((first, second)) = errors.split_once("\x1B]8;") {
                            if let Some((_, third)) = second.split_once("\x1B\\") {
                                errors = format!("{first}{third}");
                            } else {
                                break;
                            }
                        }
                        ansi_to_html::convert(&errors).unwrap()
                    },
                    if has_error {
                        "alert alert-danger"
                    } else {
                        "alert alert-warning"
                    },
                )
            };

            output.set_inner_html(&output_msg);
            output.set_class_name(class);
        }
    }) as Box<dyn FnMut(_)>);

    input.add_event_listener_with_callback("input", cb.as_ref().unchecked_ref())?;
    phase.add_event_listener_with_callback("input", cb.as_ref().unchecked_ref())?;
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
