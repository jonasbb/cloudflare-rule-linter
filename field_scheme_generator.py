"""
Generates Wirefilter field scheme code and HTML documentation from Cloudflare's field definitions.
"""

import yaml
import requests


def replace_content(
    file: str, start_marker: str, end_marker: str, new_content: str
) -> None:
    """
    Replaces the content between start_marker and end_marker in the specified file with new_content.
    """

    with open(file, "r") as f:
        content = f.read()

    start_index = content.find(start_marker)
    end_index = content.find(end_marker)

    if start_index == -1 or end_index == -1:
        raise ValueError("Start or end marker not found in the file.")

    new_content_full = (
        content[: start_index + len(start_marker)]
        + "\n"
        + new_content
        + "\n"
        + content[end_index:]
    )

    with open(file, "w") as f:
        f.write(new_content_full)


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
    "Number": "Type::Int",
    "String": "Type::Bytes",
}
"""Maps from the type in the YAML file to the necessary Rust code"""

TY_OVERWRITES: dict[str, str] = {}
"""Maps from field name to Wirefilter type, for fields that have a different type than the one loaded from the YAML file"""

DEPRECATIONS: dict[str, str] = {}
"""Maps from old to new name"""


def add_field_scheme() -> None:
    """
    Generate the field scheme from the Cloudflare docs YAML file and generates the matching wirefilter code.
    """

    # Fetch and parse the YAML file from the Cloudflare docs repository
    yaml_file = requests.get(
        "https://raw.githubusercontent.com/cloudflare/cloudflare-docs/HEAD/src/content/fields/index.yaml",
        timeout=10,
    )
    data = yaml.safe_load(yaml_file.text)
    # Sort entries by name
    data["entries"].sort(key=lambda x: x["name"])

    # last section, prints separator
    last_section = None

    schema_field_definitions = ""
    schema_field_definitions += "// Standard field definitions\n"

    for entry in data["entries"]:
        name = entry["name"]
        ty = entry["data_type"]
        keywords = entry["keywords"]
        wf_type = TYPE_TO_WIREFILTER_TYPE[ty]
        if name in TY_OVERWRITES:
            wf_type_fixed = TY_OVERWRITES[name]
            assert (
                wf_type != wf_type_fixed
            ), f"Type overwrite for {name} is the same as the original type"
            wf_type = wf_type_fixed

        section = name.split(".")[0]
        if section != last_section:
            if last_section is not None:
                schema_field_definitions += "\n"
            last_section = section
            # print section header
            schema_field_definitions += f"// {section.capitalize()} Fields\n"
        schema_field_definitions += (
            f'builder.add_field("{name}", {wf_type}).unwrap();\n'
        )

        # Check for values in keywords that looks like a deprecated name
        # We just check for anything containing a `.`
        for kw in keywords:
            if "." in kw:
                schema_field_definitions += f"// Old name for {name}\n"
                schema_field_definitions += (
                    f'builder.add_field("{kw}", {wf_type}).unwrap();\n'
                )
                DEPRECATIONS[kw] = name

    replace_content(
        "./cloudflare_rules/src/scheme.rs",
        "// GENERATED_SCHEMA_FIELDS_START",
        "// GENERATED_SCHEMA_FIELDS_END",
        schema_field_definitions,
    )


def add_deprecation_replacements() -> None:
    """
    Generate the deprecation replacement list.
    """
    deprecation_replacements = ""

    deprecation_replacements += "BTreeMap::from([\n"
    for old, new in DEPRECATIONS.items():
        deprecation_replacements += f"""    ("{old}", "{new}"),\n"""
    deprecation_replacements += "])"

    replace_content(
        "./cloudflare_rules/src/linter/deprecated_field.rs",
        "// GENERATED_DEPRECATION_REPLACEMENTS_START",
        "// GENERATED_DEPRECATION_REPLACEMENTS_END",
        deprecation_replacements,
    )


def main() -> None:
    add_field_scheme()
    add_deprecation_replacements()


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
