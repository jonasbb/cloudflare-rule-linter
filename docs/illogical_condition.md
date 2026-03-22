# Lint `illogical_condition`

The comparison is always true or always false.
For example, `http.host eq "example.com" and http.host eq "example.org"`.
The field `http.host` cannot be both values at the same time, thus this expression always evaluates as false.
This usually indicates some issues.
