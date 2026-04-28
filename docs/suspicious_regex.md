# Lint `suspicious_regex`

Detect regexes that look like they should be wildcard matches or that contain unescaped literal special characters (for example, `.` or `?`). These are common mistakes when users intend simple wildcard-style matching or literal dots in hosts, paths, or URIs.

Examples of patterns that will trigger this lint:

- `/*/foo/bar/baz` — the `*` quantifier is applied to a `/`, which usually indicates a wildcard intent rather than matching multiple slashes.
- `/foo/bar/baz/*` — trailing `/*` on a path is often intended as a wildcard segment.
- `/foo/bar/index.html` — unescaped `.` matches any character; escape as `\\.` if you intend a literal dot.
- `example.com` — unescaped dots in hostnames should usually be escaped as `\\.` or matched with a wildcard.
- `https://www.example.org/foo/index.html?query=args` — both `.` and `?` should be escaped when used literally in a regex.

Examples that do not trigger this lint:

- `/foo/[.apc]` — the `.` is inside a character class and is matched literally.
- `/foo/bar/index\\.html` — the `.` is already escaped.

When this lint fires, consider either escaping special characters (e.g., `\\.` and `\\?`) or switching to the rules-language wildcard match for simpler intent expression.
