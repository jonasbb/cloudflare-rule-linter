# Linting Rules

## Wishlist

### Mixed comparison style

Warn when both `==` and `eq` are used in the same rule. In general, only English style or C-style operators should be used.

As a variation, a general preference for either style and warning when finding the other one.

## Simplify lists

Warn on duplicate entries in lists (`{80 443 443}`) and warn on using ranges with a single element like `80..80`.

## Combine string comparison operators

Multiple string matches that are combined with `or` might be able to be merged.
For example: `A eq "foo" or A eq "bar"` => `A in {"foo" "bar"}`.

## Tautological statements

Find statements that are always true or always false.
This might overlap with some of the other rules mentioned here.
For example, two `eq` comparisons combined with `and` like `A eq "foo" and A eq "bar`.

## Preferred style for single match

The language allows multiple different ways to achieve the same goal.
For example, the string matches `A eq "foo"` and `A in {"foo"}` are semantically identical, but changing the operator is simpler in the first variant, but adding more matches is simpler in the second.

## Warn on bogon IP addresses

Bogon IP addresses should not appear on the wider internet and using them in rules can indicate problems.
For example, `ip.src eq 10.0.0.0/8`.

## Combine multiple levels of combining operators

Merge `(A or B) or C ` to `A or B or C`.
Similar for `and` and arbitrary length of combinators.

## Consider case-ness and possible values of variables

`http.request.method` always has uppercase values like `"GET"` and `http.request.uri.path.extension` is only lowercase.
Thus a rule like `http.request.method eq "get"` does not work.

A full_uri always contains the protocol, i.e., `https://`.
A path always starts with a `/`.

Port numbers are restricted in the 0..2^16 range.

## Using functions if variables exist

`substring(http.request.uri.path, -5)` or `ends_with(http.request.uri.path, ".html")` might be better served by using `http.request.uri.path.extension`.

## Remove unnecessary braces

`(A eq "foo") or (B eq "foo")` can be simplified to `A eq "foo" or B eq "foo"`.

## Simplify negation of comparisons

Simplify `not A eq "foo"` to `A ne "foo"`.

## Syntax confusion for string comparisons

A wildcard match with `.*` or a regex match with just `*`/`?` could mean that the wrong operator was used.
This might be high in false positives, or the rules must be very specific, like `matches r"/*/foobar"`.

## Limit the value of time comparisons

The value `http.request.timestamp.sec` can be used to make time based rules, e.g., rules that activate/deactivate at a specific time.
For them it makes little sense to pick a time too far in the future, e.g., 100 years.
Similarly, using values that are too small, e.g., 9-digits instead of the guaranteed 10-digits, indicate a typo.

## Regex matches only with raw strings

The language has a special escaping mode for regex matches.
This only triggers using the `matches` keyword, but not for regex functions.
The escaping is different from normal string escapes.

It is simpler and less ambiguous to not use this mode and require all regex uses to use raw strings.

This is implemented in the `lex_regex_from_literal` function.

<https://developers.cloudflare.com/ruleset-engine/rules-language/values/#quoted-string-syntax>
