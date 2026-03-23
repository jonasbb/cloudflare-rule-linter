# Lint `unnecessary_patterns`

Detect regex and wildcard patterns that can be simplified to `eq` or `contains` expressions.
Using wildcard and regex patterns indicates a level of complexity that is not present and thus can be confusing.

Strict wildcard matches preserve case, thus they can be rewritten.
`http.host strict wildcard "example"` can be simplified to `http.host strict eq "example"`.

A simple regex that matches a full string like `http.host matches "^example$"` can also be rewritten to use "eq" `http.host eq "example"`.
Regex with alterations such as `http.host matches "^(?:ex|am|ple)$"` can instead be rewritten with a list `http.host in {"ex" "am" "ple"}`.
