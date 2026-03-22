# Lint `invalid_list_name`

Compares the list names against a list of configured names.
The predefined lists from Cloudflare, like `$cf.vpn` are already preconfigured.
For custom lists, the lint only triggers if available list names are provided.

## Configuration

```toml
[settings]
invalid_list_name_custom_lists = ["allowlist_ips"]
```
