# Lint `regex_limit`

Cloudflare allows at most 64 regular expressions in a rule. This lint counts expressions using the `matches` operator and the `regex_replace` function. Rules above the limit cannot be created or updated.

## Configuration

The limit can be changed with the `regex_expression_limit` setting:

```toml
[settings]
regex_expression_limit = 64
```
