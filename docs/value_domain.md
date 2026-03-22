# Lint `value_domain`

Checks that values are sensible in their usage.
For example, all values of `http.request.method` are always uppercase, thus a comparison like `http.request.method eq "get"` will always evaluate to false.

Many fields are supported for this lint.
Here are some examples:

* `cf.edge.server_port` Port numbers are always in the range 1 to 65535.
* `http.host` follow the pattern `<host>` or `<host>:<port>`, thus no `/` can be present.
* `http.request.full_uri` always starts with the protocol like `https://`.
* `http.request.uri.path` a path always starts with a `/` character
* `ip.src.continent` can only be one of these values: "AF", "AN", "AS", "EU", "NA", "OC", "SA", "T1".
