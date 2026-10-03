#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12"
# dependencies = ["requests", "PyYAML"]
# ///

"""
Generates Wirefilter field scheme code and HTML documentation from Cloudflare's field definitions.
"""

import dataclasses
import os
import stat
import tempfile
from pathlib import Path

import requests
import yaml


@dataclasses.dataclass
class FieldInformation:
    """
    Collect information about CF fields
    """

    wf_type: str
    "Well-formed type for the field"
    is_response: bool
    "Mark this field as only available in the response phase"
    deprecated_names: list[str] = dataclasses.field(default_factory=list)
    "List of other names that are deprecated versions of this"


def replace_content(
    file: str, start_marker: str, end_marker: str, new_content: str
) -> None:
    """
    Replaces the content between start_marker and end_marker in the specified file with new_content.
    """

    path = Path(file)
    with path.open("r", encoding="utf-8") as f:
        content = f.read()

    if content.count(start_marker) != 1 or content.count(end_marker) != 1:
        raise ValueError("Start and end markers must each appear exactly once.")

    start_index = content.find(start_marker)
    end_index = content.find(end_marker)
    content_start = start_index + len(start_marker)
    if end_index < content_start:
        raise ValueError("End marker must appear after the start marker.")

    new_content_full = (
        content[:content_start]
        + "\n"
        + new_content
        + "\n"
        + content[end_index:]
    )

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as temporary_file:
            temporary_file.write(new_content_full)
            temporary_path = Path(temporary_file.name)

        os.chmod(temporary_path, stat.S_IMODE(path.stat().st_mode))
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


TYPE_TO_WIREFILTER_TYPE = {
    "Array<Array<String>>": "Type::Array(Type::Array(Type::Bytes.into()).into())",
    "Array<Integer>": "Type::Array(Type::Int.into())",
    "Array<Number>": "Type::Array(Type::Int.into())",
    "Array<String>": "Type::Array(Type::Bytes.into())",
    "Boolean": "Type::Bool",
    "Bytes": "Type::Bytes",
    "Integer": "Type::Int",
    "IP address": "Type::Ip",
    "Map<Array<Integer>>": "Type::Map(Type::Array(Type::Int.into()).into())",
    "Map<Array<String>>": "Type::Map(Type::Array(Type::Bytes.into()).into())",
    "Map<Number>": "Type::Map(Type::Int.into())",
    "Number": "Type::Int",
    "String": "Type::Bytes",
}
"""Maps from the type in the YAML file to the necessary Rust code"""

TY_OVERWRITES: dict[str, str] = {}
"""Maps from field name to Wirefilter type, for fields that have a different type than the one loaded from the YAML file"""

def get_field_scheme() -> tuple[dict[str, FieldInformation], dict[str, str]]:
    """
    Fetches the Cloudflare field scheme and deprecated-name replacements.
    """

    # Fetch and parse the YAML file from the Cloudflare docs repository
    yaml_file = requests.get(
        "https://raw.githubusercontent.com/cloudflare/cloudflare-docs/HEAD/src/content/fields/index.yaml",
        timeout=10,
    )
    yaml_file.raise_for_status()
    data = yaml.safe_load(yaml_file.text)
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise TypeError("Cloudflare field YAML must contain an entries list.")

    scheme: dict[str, FieldInformation] = {}
    deprecations: dict[str, str] = {}

    for index, entry in enumerate(data["entries"]):
        if not isinstance(entry, dict):
            raise TypeError(f"Field entry {index} must be a mapping.")
        required_fields = ("name", "data_type", "keywords", "categories")
        if any(field not in entry for field in required_fields):
            raise ValueError(f"Field entry {index} is missing a required property.")

        name = entry["name"]
        ty = entry["data_type"]
        keywords = entry["keywords"]
        categories = entry["categories"]
        if (
            not isinstance(name, str)
            or not isinstance(ty, str)
            or not isinstance(keywords, list)
            or not all(isinstance(keyword, str) for keyword in keywords)
            or not isinstance(categories, list)
        ):
            raise TypeError(f"Field entry {index} has invalid property types.")

        try:
            wf_type = TYPE_TO_WIREFILTER_TYPE[ty]
        except KeyError as error:
            raise ValueError(
                f"Unsupported data type {ty!r} for field {name!r}."
            ) from error
        if name in TY_OVERWRITES:
            wf_type_fixed = TY_OVERWRITES[name]
            if wf_type == wf_type_fixed:
                raise ValueError(f"Type overwrite for {name!r} matches its source type.")
            wf_type = wf_type_fixed

        add_field(scheme, name, FieldInformation(wf_type, "Response" in categories))

        # Check for values in keywords that looks like a deprecated name
        # We just check for anything containing a `.`
        for kw in keywords:
            if "." in kw:
                previous_name = deprecations.get(kw)
                if previous_name is not None and previous_name != name:
                    raise ValueError(
                        f"Deprecated field name {kw!r} maps to both "
                        f"{previous_name!r} and {name!r}."
                    )
                if previous_name is None:
                    scheme[name].deprecated_names.append(kw)
                    deprecations[kw] = name

    validate_deprecation_names(scheme, deprecations)
    return scheme, deprecations


def add_field(
    scheme: dict[str, FieldInformation], name: str, info: FieldInformation
) -> None:
    if name in scheme:
        raise ValueError(f"Duplicate field name: {name!r}.")
    scheme[name] = info


def validate_deprecation_names(
    scheme: dict[str, FieldInformation], deprecations: dict[str, str]
) -> None:
    collisions = sorted(scheme.keys() & deprecations.keys())
    if collisions:
        raise ValueError(
            f"Deprecated field names conflict with current fields: {collisions!r}."
        )


def emit_field_scheme(
    scheme: dict[str, FieldInformation], file: str, start_marker: str, end_marker: str
) -> None:
    """
    Generate the field scheme from the Cloudflare docs YAML file and generates the matching wirefilter code.
    """

    # last section, prints separator
    last_section = None

    schema_field_definitions = ""
    schema_field_definitions += "// Standard field definitions\n"

    for name, info in sorted(scheme.items()):
        section = name.split(".")[0]
        if section != last_section:
            if last_section is not None:
                schema_field_definitions += "\n"
            last_section = section
            # print section header
            schema_field_definitions += f"// {section.capitalize()} Fields\n"
        if info.is_response:
            schema_field_definitions += (
                "if is_response {"
                f'builder.add_field("{name}", {info.wf_type}).unwrap();\n'
                "}"
            )
        else:
            schema_field_definitions += (
                f'builder.add_field("{name}", {info.wf_type}).unwrap();\n'
            )
        for old_name in info.deprecated_names:
            schema_field_definitions += f"// Deprecated alias for {name}\n"
            if info.is_response:
                schema_field_definitions += (
                    "if is_response {"
                    f'builder.add_field("{old_name}", {info.wf_type}).unwrap();\n'
                    "}"
                )
            else:
                schema_field_definitions += (
                    f'builder.add_field("{old_name}", {info.wf_type}).unwrap();\n'
                )

    replace_content(
        file,
        start_marker,
        end_marker,
        schema_field_definitions,
    )


def add_deprecation_replacements(deprecations: dict[str, str]) -> None:
    """
    Generate the deprecation replacement list.
    """
    deprecation_replacements = ""

    deprecation_replacements += "BTreeMap::from([\n"
    for old, new in sorted(deprecations.items()):
        deprecation_replacements += f"""    ("{old}", "{new}"),\n"""
    deprecation_replacements += "])"

    replace_content(
        "./cloudflare_rules/src/linter/deprecated_field.rs",
        "// GENERATED_DEPRECATION_REPLACEMENTS_START",
        "// GENERATED_DEPRECATION_REPLACEMENTS_END",
        deprecation_replacements,
    )


def main() -> None:
    scheme, deprecations = get_field_scheme()

    # Fixup some information that are not correct in the YAML file
    # This indicates that some fields are actually response phase
    # https://github.com/cloudflare/cloudflare-docs/blob/3d99ea1499816fb085af9e22d629c96a85a43ecd/src/content/partials/rules/transform/header-modification-fields.mdx
    scheme["cf.timings.edge_msec"].is_response = True
    scheme["cf.timings.origin_ttfb_msec"].is_response = True
    scheme["cf.timings.worker_msec"].is_response = True

    # Add extra fields that are not mentioned in the official docs
    add_field(
        scheme,
        "true",
        FieldInformation(TYPE_TO_WIREFILTER_TYPE["Boolean"], False),
    )
    # Used for account level rulesets
    # https://developers.cloudflare.com/ruleset-engine/managed-rulesets/deploy-managed-ruleset/#deploy-a-managed-ruleset-to-a-phase-at-the-account-level
    # Potentially limited to PRO/BIZ/ENT
    # https://github.com/doctena-org/octorules-cloudflare/blob/b02cb8a841fb8b230c36535932ff5188c7b40863/tests/test_linter/test_action_validator.py#L221
    add_field(
        scheme,
        "cf.zone.plan",
        FieldInformation(TYPE_TO_WIREFILTER_TYPE["String"], False),
    )
    # raw.http.request.headers is listed in some "Available fields and functions", but not in the scheme
    add_field(
        scheme,
        "raw.http.request.headers",
        FieldInformation(TYPE_TO_WIREFILTER_TYPE["Map<Array<String>>"], False),
    )
    add_field(
        scheme,
        "raw.http.request.headers.names",
        FieldInformation(TYPE_TO_WIREFILTER_TYPE["Array<String>"], False),
    )
    add_field(
        scheme,
        "raw.http.request.headers.values",
        FieldInformation(TYPE_TO_WIREFILTER_TYPE["Array<String>"], False),
    )

    # Threat intelligence fields
    # https://developers.cloudflare.com/waf/detections/threat-intelligence/fields/
    # Dataset that flagged the IP address. Values: ddos, waf.
    add_field(
        scheme,
        "cf.intel.ip.datasets",
        FieldInformation(TYPE_TO_WIREFILTER_TYPE["Array<String>"], False),
    )
    # Industries this IP address has targeted. Refer to target industries for valid values.
    add_field(
        scheme,
        "cf.intel.ip.target_industries",
        FieldInformation(TYPE_TO_WIREFILTER_TYPE["Array<String>"], False),
    )
    # Threat actor names associated with this IP address (for example, CONVOLUTEDKRILL).
    add_field(
        scheme,
        "cf.intel.ip.attacker_names",
        FieldInformation(TYPE_TO_WIREFILTER_TYPE["Array<String>"], False),
    )
    # Source countries of the threat activity, as ISO 3166-1 Alpha 2 ↗ codes.
    add_field(
        scheme,
        "cf.intel.ip.attacker_countries",
        FieldInformation(TYPE_TO_WIREFILTER_TYPE["Array<String>"], False),
    )
    # Countries this IP address has targeted, as ISO 3166-1 Alpha 2 ↗ codes.
    add_field(
        scheme,
        "cf.intel.ip.target_countries",
        FieldInformation(TYPE_TO_WIREFILTER_TYPE["Array<String>"], False),
    )

    validate_deprecation_names(scheme, deprecations)

    request_mid_fields = {
        "http.request.body.*",
        "cf.waf.*",
    }
    phase_custom_rules = {
        "cf.api_gateway.*",
        "cf.fraud.*",
        "http.request.jwt.*",
    }
    request_late_fields = {
        "cf.verified_bot_category",
        "cf.bot_management.*",
        # Not verified
        "cf.intel.*",
        # Not verified
        "cf.llm.*",
    }
    response_fields = {
        "cf.timings.edge_msec",
        "cf.timings.origin_ttfb_msec",
        "cf.timings.worker_msec",
        "cf.response.*",
        "http.response.*",
        "raw.http.response.*",
    }
    phase_field_sets = {
        "requests mid": request_mid_fields,
        "phase custom rules": phase_custom_rules,
        "requests late": request_late_fields,
        "response": response_fields,
    }
    for name in scheme:
        matching_phases = [
            phase
            for phase, patterns in phase_field_sets.items()
            if name_in_wildcard_set(name, patterns)
        ]
        if len(matching_phases) > 1:
            raise ValueError(
                f"Field {name!r} matches multiple phase groups: {matching_phases!r}."
            )

    add_deprecation_replacements(deprecations)

    # Add a section with all fields
    emit_field_scheme(
        {name: wf_type for name, wf_type in scheme.items()},
        "./cloudflare_rules/src/scheme.rs",
        "// GENERATED_SCHEMA_FIELDS_START",
        "// GENERATED_SCHEMA_FIELDS_END",
    )

    emit_field_scheme(
        {
            name: wf_type
            for name, wf_type in scheme.items()
            if name_in_wildcard_set(name, request_mid_fields)
        },
        "./cloudflare_rules/src/scheme.rs",
        "// GENERATED_SCHEMA_FIELDS_REQUESTS_MID_START",
        "// GENERATED_SCHEMA_FIELDS_REQUESTS_MID_END",
    )

    emit_field_scheme(
        {
            name: wf_type
            for name, wf_type in scheme.items()
            if name_in_wildcard_set(name, phase_custom_rules)
        },
        "./cloudflare_rules/src/scheme.rs",
        "// GENERATED_SCHEMA_FIELDS_PHASE_CUSTOM_RULES_START",
        "// GENERATED_SCHEMA_FIELDS_PHASE_CUSTOM_RULES_END",
    )

    emit_field_scheme(
        {
            name: wf_type
            for name, wf_type in scheme.items()
            if name_in_wildcard_set(name, request_late_fields)
        },
        "./cloudflare_rules/src/scheme.rs",
        "// GENERATED_SCHEMA_FIELDS_REQUESTS_LATE_START",
        "// GENERATED_SCHEMA_FIELDS_REQUESTS_LATE_END",
    )

    emit_field_scheme(
        {
            name: wf_type
            for name, wf_type in scheme.items()
            if name_in_wildcard_set(name, response_fields)
        },
        "./cloudflare_rules/src/scheme.rs",
        "// GENERATED_SCHEMA_FIELDS_RESPONSE_START",
        "// GENERATED_SCHEMA_FIELDS_RESPONSE_END",
    )

    # Emit the rest as early phase
    emit_field_scheme(
        {
            name: wf_type
            for name, wf_type in scheme.items()
            if not name_in_wildcard_set(name, request_mid_fields)
            and not name_in_wildcard_set(name, phase_custom_rules)
            if not name_in_wildcard_set(name, request_late_fields)
            and not name_in_wildcard_set(name, response_fields)
        },
        "./cloudflare_rules/src/scheme.rs",
        "// GENERATED_SCHEMA_FIELDS_REQUESTS_EARLY_START",
        "// GENERATED_SCHEMA_FIELDS_REQUESTS_EARLY_END",
    )


def name_in_wildcard_set(name: str, wildcard_set: set[str]) -> bool:
    """
    Checks if the given name matches any of the wildcard patterns in the set.
    The wildcard patterns can contain a `*` at the end, which matches any suffix.
    """
    for pattern in wildcard_set:
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            if name.startswith(prefix):
                return True
        elif name == pattern:
            return True
    return False


if __name__ == "__main__":
    main()

# print("#" * 30 + "\nHTML Documentation\n" + "#" * 30 + "\n")

# # last section, prints separator
# last_section = None

# for entry in data["entries"]:
#     name = entry["name"]

#     section = name.split(".")[0]
#     if section != last_section:
#         if last_section is not None:
#             print("</ul>\n")
#         last_section = section
#         # print section header
#         print(f"<h4>{section.upper()} Fields</h4>\n<ul>")

#     print(f"  <li><code>{name}</code></li>")

# print("\n</ul>\n")
