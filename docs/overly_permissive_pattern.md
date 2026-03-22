# Lint `overly_permissive_pattern`

Detect overly permissive patterns that match against all possible values.
A regex like `.*` or a wildcard pattern like `*` will always evaluate to true.
This indicates an error in the expression or that the expression can be removed.
