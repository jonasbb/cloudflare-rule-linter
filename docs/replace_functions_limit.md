# Lint `replace_functions_limit`

The two functions `regex_replace` and `wildcard_replace` have some usage limits.
Each function can be used at most once.
The functions are not allowed to be nested inside each other, but can co-exist next to each other.
