# Lint `hostname_suffix`

Checks that hostname comparisons use the configured zone suffix.
The lint checks `http.host` and hostnames in `http.request.full_uri` and `raw.http.request.full_uri`.
For URL fields, only the URL's hostname is checked; the scheme, port, path, and query string are ignored.
This can catch typos in the hostnames, detect wrong TLDs (e.g., `example.com` vs. `example.org`), and spelling variants (e.g., `example.com` vs. `ex-ample.com`).

This only runs if the `zone_suffix` config is set to a non-empty value.

Configuration example (in JSON/TOML/your config format):

```toml
[settings]
zone_suffix = "example.com"
```
