#!/usr/bin/env python3
"""Stage development chart catalog metadata without changing release sources."""
from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path


def replace_annotation(text: str, name: str, value: str) -> str:
    """Replace one known Chart.yaml annotation, including its literal block."""
    lines = text.splitlines()
    prefix = f"  artifacthub.io/{name}:"
    matches = [i for i, line in enumerate(lines) if line.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {prefix.strip()} annotation")
    start = matches[0]
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or lines[end].startswith("    ")):
        end += 1
    lines[start:end] = (prefix + " " + value).splitlines()
    return "\n".join(lines) + "\n"


def stage_chart(source: Path, destination: Path, image: str, platform: str) -> None:
    if not re.fullmatch(r"[a-z0-9./-]+:main-[0-9]{14}-[0-9a-f]{7}", image):
        raise ValueError("expected the main development image tag")
    if platform not in {"linux/arm64", "linux/amd64"}:
        raise ValueError("unsupported published image platform")
    text = (source / "Chart.yaml").read_text(encoding="utf-8")
    text = replace_annotation(text, "prerelease", '"true"')
    # The main lane publishes one image on one native platform. It does not
    # publish the release lane's slim image or its other platform.
    images = [{"name": "helm-ai-kernel", "image": image, "platforms": [platform]}]
    text = replace_annotation(text, "images", "|\n    " + json.dumps(images))
    changes = [{"kind": "changed", "description": f"Development chart for {image}."}]
    text = replace_annotation(text, "changes", "|\n    " + json.dumps(changes))
    shutil.copytree(source, destination)
    (destination / "Chart.yaml").write_text(text, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--platform", required=True)
    args = parser.parse_args()
    try:
        stage_chart(args.source, args.destination, args.image, args.platform)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
