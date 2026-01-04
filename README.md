# Cloudflare Rules Language Linter

Cloudflare allows writing filter rules and firewall rules in their [rule language](https://developers.cloudflare.com/ruleset-engine/rules-language/).
They are inspired by Wireshark filters.

The filters can become quite complex, and logic errors can have major consequences like blocking all traffic to a website.
This repository implements a linter for the ruleset engine.
It is based on the [Cloudflare wirefilter](https://github.com/cloudflare/wirefilter), their project for parsing and executing the rules.

## Example

```text
warning[deprecated_field]: Found deprecated field ip.geoip.country
   ╭▸ ./test/example_readme.tfvars:4:27
   │
 3 │         rule_deprecated_field {
 4 │             expression = "ip.geoip.country eq \"T1\""
   │                           ━━━━━━━━━━━━━━━━━━━━━━━━━━ The value `ip.geoip.country` should be replaced with `ip.src.country`.
   ╰╴
warning[duplicate_list_entries]: Found duplicate entry in list
   ╭▸ ./test/example_readme.tfvars:7:27
   │
 6 │         rule_duplicate_list_entries {
 7 │             expression = "ip.src in {1.0.0.0/8 1.1.0.0/16}"
   ╰╴                          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ The values `1.0.0.0/8` and `1.1.0.0/16` overlap.
warning[reserved_ip_space]: Found usage of reserved IP range
   ╭▸ ./test/example_readme.tfvars:10:27
   │
 9 │         rule_reserved_ip_space {
10 │             expression = "ip.src eq 192.168.0.1"
   ╰╴                          ━━━━━━━━━━━━━━━━━━━━━ The value `192.168.0.1` is within reserved address space.
warning[negated_comparison]: Found negated comparison
   ╭▸ ./test/example_readme.tfvars:13:27
   │
12 │         rule_negated_comparison {
13 │             expression = "not http.host eq \"example.com\""
   ╰╴                          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Consider simplifying from `not http.host eq "example.com"` to `http.host ne "example.com"`
warning[regex_raw_strings]: Found regex match with non-raw string
   ╭▸ ./test/example_readme.tfvars:16:27
   │
15 │         rule_regex_raw_string {
16 │             expression = "http.host matches \"example\\.com\""
   ╰╴                          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Regex matches must use raw string literals (e.g., r"..." or r#"..."#) when using the `matches` operator.
warning[illogical_condition]: Found illogical condition with AND
   ╭▸ ./test/example_readme.tfvars:19:28
   │
18 │         rule_illogical_condition {
19 │             expression = "(http.host in { \"example.com\" }) and (http.host eq \"example.org\")"
   ╰╴                           ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ The value `http.host` is compared for equality multiple times in an AND expression.
```

## Scheme

This code relies on manually synchronizing the rule scheme from the Cloudflare documentation.
The [fields](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/) and [functions](https://developers.cloudflare.com/ruleset-engine/rules-language/functions/) are documented with their types.
If you notice any discrepancies between the scheme as implemented here compared to Cloudflares implementation, please open an issue or PR.


## Links

* <https://developers.cloudflare.com/ruleset-engine/rules-language/>
    Cloudflare documentation about their rules language, available expressions, operators, values, fields, and functions.
* <https://github.com/cloudflare/wirefilter/>
    Cloudflare repository containing the Rust code for parsing Cloudflare Rules Language.
    This contains the base framework, but the exact details of available fields and functions is not included.
* <https://github.com/gen0sec/wirefilter>
    Fork of the Cloudflare wirefilter with more functions pre-defined.
* <https://github.com/jmreicha/wirechecker>
    Simple WebUI that simulates the Cloudflare Rules Language, parses it and reports errors.
    This is based on the wirefilter crate.
* <https://raw.githubusercontent.com/cloudflare/cloudflare-docs/HEAD/src/content/fields/index.yaml>
    Wirefilter fields and types.
