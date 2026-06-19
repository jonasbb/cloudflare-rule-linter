# Lint `header_case`

Checks for usage of headers.
The lint has two different modes: It warns in cases where headers are normalized to lowercase, but the compared value is not normalized.
Other fields use unprocessed header.
Here the lint warns about any exact matches as they are fragile since they only match on one case.

The following fields are using normalized headers:

* `http.request.headers`
* `http.response.headers`
* `raw.http.request.headers`
* `raw.http.response.headers`

The following fields are using unprocessed headers:

* `http.request.headers.names`
* `http.response.headers.names`
* `raw.http.request.headers.names`
* `raw.http.response.headers.names`

Examples:

* Warns because maps normalizes the headers to lowercase: `any(http.request.headers["Authorization"][*] wildcard "Bearer *")`
* Warns because the list uses unprocessed headers and this rule if fragile due to casing differences: `any(http.response.headers.names[*] in { "content-type" })`
