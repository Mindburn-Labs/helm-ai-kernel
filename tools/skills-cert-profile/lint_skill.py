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
KEBAB_CASE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")
HELM_REQUIRED = {
    "effect_class": {
        "read_only", "write_local", "write_external", "network_egress",
        "credential_access", "code_execution", "financial", "irreversible",
    },
    "reversibility": {"none", "compensating_action", "exact_undo"},
    "data_boundary": {"local_only", "device_boundary", "org_boundary", "external"},
}
NETWORK_BINS = {"curl", "wget", "nc", "http", "https"}
MEMORY_DOMAINS = {"none", "read", "write", "read_write"}


def parse_frontmatter(text: str) -> dict:
    """Parse the YAML subset used in SKILL.md frontmatter into nested dicts."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    lines = []
    for raw in text[3:end].splitlines():
        if raw.strip() and not raw.strip().startswith("#"):
            lines.append((len(raw) - len(raw.lstrip()), raw.strip()))

    def scalar(value: str) -> str:
        return value.strip().strip('"\'')

    def parse_list(index: int, indent: int) -> tuple[list[str], int]:
        values: list[str] = []
        while index < len(lines):
            current_indent, line = lines[index]
            if current_indent != indent or not line.startswith("- "):
                break
            values.append(scalar(line[2:]))
            index += 1
        return values, index

    def parse_map(index: int, indent: int) -> tuple[dict, int]:
        result: dict = {}
        while index < len(lines):
            current_indent, line = lines[index]
            if current_indent < indent:
                break
            if current_indent != indent or line.startswith("- ") or ":" not in line:
                index += 1
                continue
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            index += 1
            if value:
                result[key] = scalar(value)
                continue
            if index >= len(lines) or lines[index][0] <= current_indent:
                result[key] = {}
                continue
            child_indent, child_line = lines[index]
            if child_line.startswith("- "):
                result[key], index = parse_list(index, child_indent)
            else:
                result[key], index = parse_map(index, child_indent)
        return result, index

    return parse_map(0, lines[0][0])[0] if lines else {}


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
    if fm.get("name") and not KEBAB_CASE.fullmatch(fm["name"]):
        problems.append("baseline: `name` must be kebab-case")
    if fm.get("version") and not SEMVER.fullmatch(fm["version"]):
        problems.append("baseline: `version` must be SemVer")

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
    memory_access = helm.get("memory_access")
    if not isinstance(memory_access, dict):
        problems.append("helm-cert: missing `metadata.helm.memory_access` block")
    else:
        for domain in ("user_domain", "agent_domain"):
            if memory_access.get(domain) not in MEMORY_DOMAINS:
                problems.append(
                    f"helm-cert: `metadata.helm.memory_access.{domain}` must be one of "
                    f"{sorted(MEMORY_DOMAINS)}"
                )
        if memory_access.get("cross_domain_read") not in (False, "false"):
            problems.append(
                "helm-cert: `metadata.helm.memory_access.cross_domain_read` "
                "must be false"
            )

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
    if sys.argv[1:] == ["--help"]:
        print(__doc__)
        return 0
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    failures = 0
    for arg in sys.argv[1:]:
        path = Path(arg)
        try:
            problems = lint(path)
        except OSError as exc:
            problems = [f"cannot read file: {exc}"]
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
