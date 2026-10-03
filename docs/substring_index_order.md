# Lint `substring_index_order`

Detects `substring()` calls where both the start and end indices are non-negative integer literals, but the end index is less than the start index. In this case, `substring()` returns an empty string.

For example, `substring(http.request.uri.path, 10, 5)` has an inverted index range. Make the end index at least as large as the start index, or use a negative index to count from the end of the string.

Negative indices are not flagged because they count from the end of the string. Calls with a dynamic index or without an explicit end index are also not flagged.
