from typing import Hashable
from .cloudflare_rules import parse_expression
import json
import dataclasses
from typing import Any


@dataclasses.dataclass(frozen=True)
class OpEq:
    left: Any
    right: Any


def cf_rules_cli() -> None:
    # ast_json = parse_expression(""" http.method == "GET" """.strip())
    # print(f"AST JSON: {ast_json}")
    # ast = json.loads(ast_json, object_hook=ast_rules_loader)
    # print(f"AST: {ast}")

    ast_json = parse_expression(
        """ http.method eq "GET" or (http.method eq "POST") or (req.srcip in {10.0.0.1 ::1 127.0.0.0/8 2002::2..2003::3}) or (port in {80..80 80}) or ((http.method matches r###"([G]ET|POST|"\\.)"### and http.method matches "GET\\.\\x1b")) """
    )
    # print(f"AST JSON: {ast_json}")
    # ast = json.loads(ast_json, object_hook=ast_rules_loader)
    # print(f"AST: {ast}")


def ast_rules_loader(d: dict[Hashable, Any]) -> Any:
    if "lhs" in d and "rhs" in d and d.get("op") == "Equal":
        return OpEq(left=d["lhs"], right=d["rhs"])
    return d
