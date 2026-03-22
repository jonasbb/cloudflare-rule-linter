# Lint `negated_comparison`

Suggests to simplify expressions to remove unnecessary `not`s that can be included into the comparison operator.
For example, `not http.host eq "example.com"` can be simplified to `http.host ne "example.com"`.
