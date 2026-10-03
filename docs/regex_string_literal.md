# Lint `regex_string_literal`

Detect string literals that look like regular expressions but are compared with an operator that does not interpret regex syntax. Only `matches` performs regex matching; operators such as `eq`, `contains`, `wildcard`, `strict wildcard`, and `in` treat these characters as ordinary string content.

The lint looks for common regex indicators:

- `^` at the beginning or an unescaped `$` at the end of a string
- Inline regex flags such as `(?i)`, `(?m)`, or `(?im)`
- POSIX-style character classes such as `[[:alnum:]]` or `[[:word:]]`

Examples that trigger this lint:

- `http.host eq "^example.com$"`
- `http.host wildcard "prefix(?i)example"`
- `http.host in {"[[:alnum:]]"}`

Use `matches` when you intend to use regular-expression syntax, or remove the syntax if you intended a literal string comparison.
