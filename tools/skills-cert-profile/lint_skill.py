#!/usr/bin/env python3
"""Lint SKILL.md files against Skills Certification Profile v1.

Stdlib-only. Parses the YAML frontmatter subset used by OpenClaw-style
SKILL.md files (nested maps, scalar lists) — sufficient for certification
field checks; not a general YAML parser.

Usage: lint_skill.py <SKILL.md> [...]
Exit 0 = all files baseline-valid AND HELM-certified fields complete.
Exit 1 = any failure (per-field report on stdout).
"""

import re
import sys
from pathlib import Path

BASELINE_REQUIRED = ["name", "description", "version"]
HELM_REQUIRED = {
    "effect_class": {
        "read_only", "write_local", "write_external", "network_egress",
        "credential_access", "code_execution", "financial", "irreversible",
    },
    "reversibility": {"none", "compensating_action", "exact_undo"},
    "data_boundary": {"local_only", "device_boundary", "org_boundary", "external"},
}
NETWORK_BINS = {"curl", "wget", "nc", "http", "https"}


def parse_frontmatter(text: str) -> dict:
    """Parse the YAML subset used in SKILL.md frontmatter into nested dicts."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    root: dict = {}
    stack: list[tuple[int, dict]] = [(-1, root)]
    last_key_at_indent: dict[int, str] = {}
    for raw in text[3:end].splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if line.startswith("- "):
            key = last_key_at_indent.get(stack[-1][0])
            if key is not None:
                if not isinstance(parent.get(key), list):
                    parent[key] = []
                parent[key].append(line[2:].strip().strip('"\''))
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if value == "":
            node: dict = {}
            parent[key] = node
            stack.append((indent, node))
            last_key_at_indent[indent - 1] = key
        else:
            parent[key] = value.strip('"\'')
            last_key_at_indent[stack[-1][0]] = key
    return root


def dig(node: dict, path: list[str]):
    cur = node
    for part in path:
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def lint(path: Path) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")
    fm = parse_frontmatter(text)
    if not fm:
        return ["no parseable frontmatter"]

    for field in BASELINE_REQUIRED:
        if not fm.get(field):
            problems.append(f"baseline: missing `{field}`")
    if fm.get("name") and fm["name"] != path.parent.name:
        problems.append(
            f"baseline: name `{fm['name']}` != directory `{path.parent.name}`"
        )

    helm = fm.get("metadata", {}).get("helm")
    if not isinstance(helm, dict):
        problems.append("helm-cert: missing `metadata.helm` block")
        helm = {}
    for field, allowed in HELM_REQUIRED.items():
        value = helm.get(field)
        if value is None:
            problems.append(f"helm-cert: missing `metadata.helm.{field}`")
        elif value not in allowed:
            problems.append(
                f"helm-cert: `metadata.helm.{field}` = {value!r} not in {sorted(allowed)}"
            )
    if helm.get("receipts", {}).get("required") not in (True, "true"):
        problems.append("helm-cert: missing `metadata.helm.receipts.required: true`")
    if not helm.get("permissions"):
        problems.append("helm-cert: missing `metadata.helm.permissions` list")

    # consistency: network tooling or credentials imply non-read-only effects
    metadata = fm.get("metadata", {})
    bins: list[str] = []
    env: list[str] = []
    for runtime_block in metadata.values():
        if isinstance(runtime_block, dict):
            requires = runtime_block.get("requires", {})
            if isinstance(requires, dict):
                bins.extend(requires.get("bins") or [])
                env.extend(requires.get("env") or [])
    effect = helm.get("effect_class")
    if effect == "read_only":
        if set(bins) & NETWORK_BINS:
            problems.append(
                f"consistency: network-capable bins {sorted(set(bins) & NETWORK_BINS)} "
                "but effect_class is read_only"
            )
        if env:
            problems.append(
                f"consistency: env credentials {env} declared but effect_class is read_only"
            )
    return problems


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    failures = 0
    for arg in sys.argv[1:]:
        path = Path(arg)
        problems = lint(path)
        if problems:
            failures += 1
            print(f"FAIL {path}")
            for p in problems:
                print(f"  - {p}")
        else:
            print(f"ok   {path}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
