# Lint `timestamp_comparisons`

Checks for comparisons of `http.request.timestamp.sec` against timestamps that are too far in the past or too far into the future.
If the value is before 1262300400 (January 2010) or more than five years into the future, the lint triggers.
Values that are too small can indicate a typo, e.g., a missing or swapped number.
Values that are too far in the future can similarly be a typo or are unreliable.

## Configuration

```toml
[settings]
# UNIX timestamp, warn if lower than this.
timestamp_bounds_min_timestamp = 1262300400
# Default value: Roughly 5 years into the future
# Number of seconds that are permitted for the future.
# 158112000 = 5 * 366 * 24 * 60 * 60
timestamp_bounds_future_delta = 158112000
```
