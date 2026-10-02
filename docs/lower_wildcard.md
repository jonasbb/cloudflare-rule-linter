# Lint `lower_wildcard`

Detects unnecessary `lower()` calls before `wildcard` comparisons. Wildcard matching is case-insensitive, so the function does not affect the result. `strict wildcard` is case-sensitive and is not flagged.

For example, `lower(http.request.uri.path) wildcard "/foo/bar/*"` can be simplified to `http.request.uri.path wildcard "/foo/bar/*"`.
