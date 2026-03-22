# Summary of all available lints

<!--START_LINT_SUMMARY-->
| Name | Category | Description |
| --- | --- | --- |
| [deprecated_field](./deprecated_field.md) | deprecated | Check for usage of old field names and suggest the correct new values. |
| [duplicate_list_entries](./duplicate_list_entries.md) | correctness | Detect duplicate values in lists. |
| [empty_list](./empty_list.md) | correctness | Check for comparisons against empty lists, which are always false. |
| [header_case](./header_case.md) | correctness | Checks for header names that are not all lowercase. |
| [illogical_condition](./illogical_condition.md) | style | Detect illogical conditions, such as comparing the same field for equality multiple times in an AND expression, or for inequality multiple times in an OR expression. |
| [invalid_list_name](./invalid_list_name.md) | correctness | Check for invalid managed list names and optionally invalid custom list names. |
| [negated_comparison](./negated_comparison.md) | style | Detect comparisons that are negated and suggest using the opposite comparison operator instead. |
| [overly_permissive_pattern](./overly_permissive_pattern.md) | correctness | Check for regex and wildcard patterns that are overly permissive. |
| [regex_raw_strings](./regex_raw_strings.md) | style | Ensure regex matches use raw string literals (r"...") instead of normal quoted strings. |
| [reserved_ip_space](./reserved_ip_space.md) | correctness | Check for usage of reserved IP ranges that are unlikely to be useful in rules. |
| [timestamp_comparisons](./timestamp_comparisons.md) | correctness | Detect comparisons against http.request.timestamp.sec that use values outside of reasonable bounds. |
| [value_domain](./value_domain.md) | correctness | Check for values that are outside of the valid domain for certain fields, such as invalid HTTP methods or invalid continents. |
<!--END_LINT_SUMMARY-->
