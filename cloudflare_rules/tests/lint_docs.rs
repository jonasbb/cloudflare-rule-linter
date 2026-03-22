//! Tests to ensure that each lint has corresponding documentation.

use std::path::Path;

#[test]
fn ensure_each_lint_has_docs() {
    let base_dir = Path::new("../docs/");
    for lint in cloudflare_rules::lint_iter() {
        let doc_path = base_dir.join(format!("{}.md", lint.name));
        assert!(
            std::path::Path::new(&doc_path).exists(),
            "Lint '{}' does not have documentation at '{}'",
            lint.name,
            doc_path.display()
        );
    }
}

#[test]
fn ensure_lint_summary_is_current() {
    // Markers, between these tags the lint summary should be up to date
    let start_tag = "<!--START_LINT_SUMMARY-->\n";
    let end_tag = "<!--END_LINT_SUMMARY-->\n";

    // All the files that should be checked for the lint summary.
    let files = [Path::new("../README.md"), Path::new("../docs/README.md")];
    let base_dir = Path::new("../docs/");

    let mut files_updates = Vec::new();
    let mut lints = cloudflare_rules::lint_iter().collect::<Vec<_>>();
    lints.sort_by_key(|lint| lint.name);

    for file in files {
        // Create a markdown table with all lints
        // The links must be relative to the file
        let mut lint_summary = String::new();
        lint_summary.push_str("| Name | Category | Description |\n");
        lint_summary.push_str("| --- | --- | --- |\n");
        for lint in &lints {
            let lint_doc_path = base_dir.join(format!("{}.md", lint.name));
            let lint_doc_path = lint_doc_path.strip_prefix(file.parent().unwrap()).unwrap();

            lint_summary.push_str(&format!(
                "| [{name}](./{path}) | {category} | {description} |\n",
                name = lint.name,
                path = lint_doc_path.display(),
                category = lint.category,
                description = lint.description,
            ));
        }

        // Check what the current summary in the file is and update it if necessary
        let content = std::fs::read_to_string(file)
            .unwrap_or_else(|_| panic!("Failed to read file '{}'", file.display()));
        let start_index = content.find(start_tag).unwrap_or_else(|| {
            panic!(
                "Start tag '{start_tag}' not found in file '{}'",
                file.display()
            )
        }) + start_tag.len();
        let end_index = content.find(end_tag).unwrap_or_else(|| {
            panic!("End tag '{end_tag}' not found in file '{}'", file.display())
        });
        let current_summary = &content[start_index..end_index];
        if current_summary != lint_summary {
            files_updates.push(file);
        }
        let new_content = format!(
            "{}{}{}",
            &content[..start_index],
            lint_summary,
            &content[end_index..]
        );
        std::fs::write(file, new_content).unwrap_or_else(|_| {
            panic!(
                "Failed to write updated content to file '{}'",
                file.display()
            )
        });
    }

    // Let the test fail if any of the files were updated, to ensure that the updates are reviewed and committed.
    if !files_updates.is_empty() {
        panic!(
            "The lint summary is not up to date in the following files: {:?}.\nThe files were \
             updated in place. Please review the changes and commit them if they look good.",
            files_updates
        );
    }
}
