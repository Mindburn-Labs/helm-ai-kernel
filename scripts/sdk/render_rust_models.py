"""Combine the OpenAPI generator's Rust model files into the public type module."""

import re
import sys
from pathlib import Path

HEADER = """// AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
// Regenerate: bash scripts/sdk/gen.sh

use serde::{Deserialize, Serialize};
"""


def render_model(path: Path) -> tuple[str, str]:
    source = "\n".join(
        line
        for line in path.read_text().splitlines()
        if not line.startswith(("use ", "pub mod", "mod "))
    )
    struct_match = re.search(r"\bpub struct ([A-Za-z0-9_]+)\b", source)
    if struct_match:
        struct_name = struct_match.group(1)
        enum_names = dict.fromkeys(re.findall(r"\bpub enum ([A-Za-z0-9_]+)\b", source))
        for enum_name in enum_names:
            source = re.sub(rf"\b{re.escape(enum_name)}\b", f"{struct_name}{enum_name}", source)
        return struct_name, source
    enum_match = re.search(r"\bpub enum ([A-Za-z0-9_]+)\b", source)
    return (enum_match.group(1) if enum_match else path.stem), source


def render_types(models_dir: Path) -> str:
    models = [render_model(path) for path in models_dir.glob("*.rs")]
    if not models:
        raise SystemExit("rs generation failed: generator produced zero model files")
    source = HEADER + "".join(snippet + "\n" for _, snippet in sorted(models, key=lambda model: model[0]))
    source = source.replace("/// \n", "///\n")
    source = source.replace("models::", "")
    source = source.replace(', with = "::serde_with::rust::double_option"', "")

    # Nested enum names must be unique in the combined module.
    for collision in ("pub enum Type {", "pub enum Verdict {", "pub enum Jsonrpc {"):
        if collision in source:
            raise SystemExit(f"rs postcondition failed: bare {collision!r} survived rendering")

    # Reason codes are open strings. Their registered names live in reason_codes.rs.
    if "pub enum HelmErrorErrorReasonCode" in source:
        raise SystemExit("rs postcondition failed: HelmError reason_code rendered as a closed enum")
    if "pub type ReasonCode = String;" not in source:
        source += "\n/// A reason code: an open string. Registered names are in `reason_codes`.\npub type ReasonCode = String;\n"
    return "\n".join(line.rstrip() for line in source.splitlines()).rstrip() + "\n"


if __name__ == "__main__":
    models_dir, output_path = map(Path, sys.argv[1:])
    output_path.write_text(render_types(models_dir), encoding="utf-8")
