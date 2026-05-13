#!/usr/bin/env python3
"""Run HELM AI Kernel quality gates from a declarative registry."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY = ROOT / "scripts" / "ci" / "quality-gates.json"
EXPECTED_GATE_IDS = {
    "docs-truth",
    "presentation-hygiene",
    "go-lint",
    "go-test",
    "go-race",
    "tcb-imports",
    "boundary-manifest",
    "codegen-drift",
    "proto-breaking",
    "json-schemas",
    "openapi-console-drift",
    "release-smoke",
    "deployment-smoke",
    "secrets",
    "vuln-audit",
    "mutation-core",
    "flake-core",
    "runbooks",
    "migrations",
}
EXPECTED_PROFILES = {
    "pr",
    "merge",
    "release",
    "nightly",
    "typecheck",
    "contracts",
    "security",
    "runbooks",
    "mutation",
    "flake",
    "impact",
}


@dataclass
class GateResult:
    gate_id: str
    status: str
    advisory: bool
    elapsed: float = 0.0


def github_escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def emit(level: str, title: str, message: str) -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level} title={github_escape(title)}::{github_escape(message)}")
    else:
        label = "warning" if level == "warning" else "error"
        print(f"{label.upper()}: {title}: {message}")


def group_start(title: str) -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::group::{github_escape(title)}")


def group_end() -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print("::endgroup::")


def load_registry(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise SystemExit(f"quality registry not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"quality registry is invalid JSON: {path}:{exc.lineno}:{exc.colno}: {exc.msg}") from exc


def gates_by_id(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    gates = registry.get("gates")
    if not isinstance(gates, list):
        raise SystemExit("quality registry must contain a gates array")
    return {str(gate.get("id")): gate for gate in gates}


def strict_enabled(args: argparse.Namespace) -> bool:
    if getattr(args, "strict", False):
        return True
    return os.environ.get("QUALITY_STRICT", "").strip().lower() in {"1", "true", "yes", "on"}


def parse_changed_files_from_env(raw: str) -> set[str]:
    files: set[str] = set()
    for chunk in raw.replace(",", "\n").splitlines():
        value = chunk.strip()
        if value:
            files.add(value)
    return files


def git_lines(args: list[str]) -> set[str] | None:
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def changed_files() -> set[str] | None:
    explicit = os.environ.get("QUALITY_CHANGED_FILES")
    if explicit:
        return parse_changed_files_from_env(explicit)

    refs: list[str] = []
    base_ref = os.environ.get("GITHUB_BASE_REF", "").strip()
    if base_ref:
        refs.extend([f"origin/{base_ref}...HEAD", f"{base_ref}...HEAD"])
    refs.extend(["origin/main...HEAD", "main...HEAD", "HEAD~1...HEAD"])

    for ref in refs:
        files = git_lines(["git", "diff", "--name-only", "--diff-filter=ACMRTUXB", ref])
        if files:
            return files

    local: set[str] = set()
    for args in (
        ["git", "diff", "--name-only", "--diff-filter=ACMRTUXB"],
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"],
        ["git", "ls-files", "--others", "--exclude-standard"],
    ):
        files = git_lines(args)
        if files:
            local.update(files)
    return local or None


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(path, pattern) for pattern in patterns)


def impacted(gate: dict[str, Any], files: set[str] | None) -> bool:
    patterns = gate.get("paths") or []
    if not patterns:
        return True
    if files is None:
        return True
    return any(matches_any(path, patterns) for path in files)


def explain_gate(gate: dict[str, Any], profile_names: list[str]) -> None:
    mode = "advisory" if gate.get("advisory", False) else "blocking"
    print(f"{gate['id']}: {gate.get('title', gate['id'])}")
    print(f"  mode: {mode}")
    print(f"  command: {gate.get('command', '')}")
    print(f"  timeout_seconds: {gate.get('timeout_seconds', 'none')}")
    if profile_names:
        print(f"  profiles: {', '.join(profile_names)}")
    if gate.get("paths"):
        print(f"  impact_paths: {', '.join(gate['paths'])}")
    if gate.get("description"):
        print(f"  description: {gate['description']}")


def list_gates(registry: dict[str, Any]) -> None:
    gates = gates_by_id(registry)
    profiles = registry.get("profiles", {})
    print("Profiles:")
    for name in sorted(profiles):
        profile = profiles[name]
        print(f"  {name}: {profile.get('description', '')}")
    print()
    print("Gates:")
    for gate_id in sorted(gates):
        gate = gates[gate_id]
        mode = "advisory" if gate.get("advisory", False) else "blocking"
        print(f"  {gate_id:<28} {mode:<9} {gate.get('title', '')}")


def profile_gate_ids(registry: dict[str, Any], profile_name: str) -> list[str]:
    profiles = registry.get("profiles", {})
    if profile_name not in profiles:
        raise SystemExit(f"unknown quality profile: {profile_name}")
    gates = profiles[profile_name].get("gates")
    if not isinstance(gates, list):
        raise SystemExit(f"profile {profile_name} must contain a gates array")
    return [str(gate_id) for gate_id in gates]


def run_gate(gate: dict[str, Any], strict: bool, env: dict[str, str]) -> GateResult:
    gate_id = str(gate["id"])
    command = str(gate.get("command", "")).strip()
    if not command:
        emit("error", gate_id, "gate has no command")
        return GateResult(gate_id, "failed", advisory=False)

    advisory = bool(gate.get("advisory", False)) and not strict
    mode = "advisory" if advisory else "blocking"
    timeout = gate.get("timeout_seconds")
    timeout_value = int(timeout) if timeout else None
    title = f"{gate_id} ({mode})"
    print(f"\n==> {title}")
    print(f"    {command}")
    group_start(title)
    started = time.monotonic()
    try:
        result = subprocess.run(command, cwd=ROOT, shell=True, env=env, timeout=timeout_value)
        status = "passed" if result.returncode == 0 else "failed"
    except subprocess.TimeoutExpired:
        result = None
        status = "timeout"
    finally:
        group_end()

    elapsed = time.monotonic() - started
    if status == "passed":
        print(f"PASS {gate_id} ({elapsed:.1f}s)")
        return GateResult(gate_id, "passed", advisory=advisory, elapsed=elapsed)

    message = f"quality gate {gate_id} {status} after {elapsed:.1f}s"
    if result is not None:
        message += f" with exit code {result.returncode}"
    if advisory:
        emit("warning", gate_id, message)
        return GateResult(gate_id, "advisory-failed", advisory=True, elapsed=elapsed)

    emit("error", gate_id, message)
    return GateResult(gate_id, status, advisory=False, elapsed=elapsed)


def run_selection(registry: dict[str, Any], args: argparse.Namespace) -> int:
    gates = gates_by_id(registry)
    if args.gate:
        selected_ids = args.gate
        selection_name = "custom"
    else:
        selected_ids = profile_gate_ids(registry, args.selection)
        selection_name = args.selection

    strict = strict_enabled(args)
    impact_files = changed_files() if args.impact else None
    if args.impact:
        if impact_files is None:
            print("impact filtering: no changed-file set found; running all selected gates")
        else:
            print(f"impact filtering: {len(impact_files)} changed path(s) detected")

    env = os.environ.copy()
    env.setdefault("QUALITY_PROFILE", selection_name)
    env["QUALITY_STRICT"] = "1" if strict else env.get("QUALITY_STRICT", "0")

    results: list[GateResult] = []
    for gate_id in selected_ids:
        if gate_id not in gates:
            emit("error", gate_id, f"profile references unknown gate {gate_id}")
            results.append(GateResult(gate_id, "failed", advisory=False))
            continue
        gate = gates[gate_id]
        if args.impact and not impacted(gate, impact_files):
            print(f"SKIP {gate_id}: no matching changed paths")
            results.append(GateResult(gate_id, "skipped", advisory=bool(gate.get("advisory", False))))
            continue
        results.append(run_gate(gate, strict=strict, env=env))

    print("\nQuality summary:")
    for result in results:
        print(f"  {result.gate_id:<28} {result.status:<16} {result.elapsed:.1f}s")

    blocking_failures = [r for r in results if r.status in {"failed", "timeout"} and not r.advisory]
    advisory_failures = [r for r in results if r.status == "advisory-failed"]
    if advisory_failures:
        print(f"Advisory failures: {len(advisory_failures)}")
    if blocking_failures:
        print(f"Blocking failures: {len(blocking_failures)}")
        return 1
    return 0


def self_test(registry: dict[str, Any]) -> int:
    failures: list[str] = []
    if registry.get("version") != 1:
        failures.append("registry version must be 1")

    gates = registry.get("gates")
    profiles = registry.get("profiles")
    if not isinstance(gates, list):
        failures.append("gates must be a list")
        gates = []
    if not isinstance(profiles, dict):
        failures.append("profiles must be an object")
        profiles = {}

    seen: set[str] = set()
    gate_ids: set[str] = set()
    for gate in gates:
        if not isinstance(gate, dict):
            failures.append("every gate must be an object")
            continue
        gate_id = str(gate.get("id", "")).strip()
        if not gate_id:
            failures.append("gate has blank id")
            continue
        if gate_id in seen:
            failures.append(f"duplicate gate id: {gate_id}")
        seen.add(gate_id)
        gate_ids.add(gate_id)
        if not str(gate.get("command", "")).strip():
            failures.append(f"{gate_id}: command is required")
        if "timeout_seconds" in gate and int(gate["timeout_seconds"]) <= 0:
            failures.append(f"{gate_id}: timeout_seconds must be positive")
        if "paths" in gate and not isinstance(gate["paths"], list):
            failures.append(f"{gate_id}: paths must be a list")
        if "advisory" in gate and not isinstance(gate["advisory"], bool):
            failures.append(f"{gate_id}: advisory must be a boolean")

    for gate_id in sorted(EXPECTED_GATE_IDS - gate_ids):
        failures.append(f"missing required gate id: {gate_id}")

    profile_ids = set(profiles)
    for profile_id in sorted(EXPECTED_PROFILES - profile_ids):
        failures.append(f"missing required profile: {profile_id}")
    for profile_id, profile in profiles.items():
        if not isinstance(profile, dict):
            failures.append(f"profile {profile_id} must be an object")
            continue
        profile_gates = profile.get("gates")
        if not isinstance(profile_gates, list) or not profile_gates:
            failures.append(f"profile {profile_id} must define at least one gate")
            continue
        for gate_id in profile_gates:
            if gate_id not in gate_ids:
                failures.append(f"profile {profile_id} references unknown gate: {gate_id}")

    if failures:
        print("Quality registry self-test failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"Quality registry self-test passed: {len(gate_ids)} gates, {len(profiles)} profiles.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY), help="Path to quality-gates.json")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List quality profiles and gates")

    explain = subparsers.add_parser("explain", help="Explain a single gate")
    explain.add_argument("gate_id")

    run = subparsers.add_parser("run", help="Run a profile or explicit gate set")
    run.add_argument("selection", nargs="?", default="pr", help="Profile name when --gate is not used")
    run.add_argument("--gate", action="append", help="Run one gate id; may be repeated")
    run.add_argument("--impact", action="store_true", help="Skip path-scoped gates that are not impacted")
    run.add_argument("--strict", action="store_true", help="Treat advisory gates as blocking")

    subparsers.add_parser("self-test", help="Validate the quality registry")

    args = parser.parse_args()
    registry = load_registry(Path(args.registry))

    if args.command == "list":
        list_gates(registry)
        return 0
    if args.command == "explain":
        gates = gates_by_id(registry)
        if args.gate_id not in gates:
            raise SystemExit(f"unknown quality gate: {args.gate_id}")
        profiles = registry.get("profiles", {})
        profile_names = [
            name for name, profile in sorted(profiles.items()) if args.gate_id in profile.get("gates", [])
        ]
        explain_gate(gates[args.gate_id], profile_names)
        return 0
    if args.command == "run":
        return run_selection(registry, args)
    if args.command == "self-test":
        return self_test(registry)
    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
