# Lint `hostname_suffix`

Checks that comparisons with `http.host` are sensible by comparing them against the known suffix of the zone.
This can catch typos in the hostnames, detect wrong TLDs (e.g., `example.com` vs. `example.org`), and spelling variants (e.g., `example.com` vs. `ex-ample.com`)

This only runs if the `zone_suffix` config is set to a non-empty value.

Configuration example (in JSON/TOML/your config format):

```toml
[settings]
zone_suffix = "example.com"
```
