# operator_style

Category: style

Enforce a consistent operator notation across a rule expression. The lint supports three modes via configuration:

- `EnforceEnglish`: require use of English operator names such as `eq`, `ge`, `matches`, `and`, `not`.
- `EnforceCLike`: require use of C-like operator symbols such as `==`, `>=`, `~`, `&&`, `!`.
- `ProhibitMixed` (default): detect the first operator style used in the rule and require all subsequent operators in the same rule to use the same style.

Operators that only exist in English (for example, `in`, `wildcard`, `contains`) are ignored by this lint.

Examples

- Allowed (English): `http.host eq "abc" and http.host eq "def"`
- Allowed (C-like): `http.host == "abc" && http.host == "def"`
- Error (mixed): `http.host == "abc" && http.host eq "def"`

Configuration example (in JSON/TOML/your config format):

```toml
[settings]
# Enforce English notation
operator_style_mode = "EnforceEnglish"

# Enforce C-like notation
operator_style_mode = "EnforceCLike"

# Prohibit mixing (default)
operator_style_mode = "ProhibitMixed"
```
