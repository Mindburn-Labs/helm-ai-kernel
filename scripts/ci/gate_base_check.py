#!/usr/bin/env python3
"""Hold a change to the gate its base branch defines.

`make check` runs the merge profile of scripts/ci/quality-gates.json, and that
file comes from the change under test. Without this check a pull request could
drop gosec, govulncheck or go-test from the merge profile and pass the very
gate it weakened. This check reads the merge profile from the base commit and
fails when a gate the base runs is missing from the change's merge profile,
unless scripts/ci/gate-removals.json in the change names that gate with a
reason. The removal then shows in the diff and in the check's output.

When the base carries this script, the copy in the change hands over to the
base's copy, so an edit to the rules here (what counts as a removal, how an
acknowledgement is read) does not change the verdict on the change that makes
it.

Limit: the hand-over is code in the change, and so is the `check` target that
starts this script. A change that removes either one skips the check. Both
edits are in the diff and carry the tier-2 label, which does not hold a merge;
closing this needs the check to run from the shared workflow, outside the
change. A changed command of a gate that stays in the profile is reported as a
warning, not held.

A push to main whose commit a merge group already gated is not judged again:
that run checked each queued change against its own base, and the push may span
several of them.

Base commit:
  merge_group   merge_group.base_sha from the event payload
  pull_request  merge-base of origin/$GITHUB_BASE_REF and HEAD
  push          the event's `before` commit (the previous tip of the branch)
  local run     merge-base of origin/main and HEAD

Exit codes: 0 when every base gate still runs or its removal is acknowledged,
1 on an unacknowledged removal or a malformed acknowledgement, 2 when the base
commit is unknown or its objects are not in the checkout in CI. A local run
without a readable base commit prints NOT RUN and exits 0, because there is
nothing to compare against; CI never takes that path.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REGISTRY = "scripts/ci/quality-gates.json"
REMOVALS = "scripts/ci/gate-removals.json"
SELF = "scripts/ci/gate_base_check.py"
PROFILE = "merge"
FROM_BASE_ENV = "GATE_BASE_CHECK_FROM_BASE"
ROOT_ENV = "GATE_BASE_CHECK_ROOT"


def repository_root() -> Path:
    """The checkout this run judges.

    The base commit's copy runs from standard input, where __file__ names no
    file in the repository, so the copy that starts it hands the root over.
    """
    handed = os.environ.get(ROOT_ENV, "")
    if os.environ.get(FROM_BASE_ENV) == "1" and handed:
        return Path(handed)
    return Path(__file__).resolve().parents[2]


ROOT = repository_root()


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)


def in_ci() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


def emit(level: str, message: str) -> None:
    if in_ci():
        print(f"::{level}::{message}")
    else:
        print(f"{level.upper()}: {message}")


def resolve_base() -> tuple[str | None, str]:
    """Return (base commit, how it was found); the commit is None when unknown."""
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    payload: dict = {}
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if event_path and Path(event_path).is_file():
        try:
            payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
    if event == "merge_group":
        sha = str(payload.get("merge_group", {}).get("base_sha", ""))
        return (sha or None), "merge_group.base_sha"
    if event == "push":
        sha = str(payload.get("before", ""))
        if sha and set(sha) != {"0"}:
            return sha, "push before"
        return None, "push without a previous commit"
    base_ref = os.environ.get("GITHUB_BASE_REF", "").strip() or "main"
    result = git("merge-base", f"origin/{base_ref}", "HEAD")
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip(), f"merge-base with origin/{base_ref}"
    return None, f"no origin/{base_ref} to compare against"


def show(commit: str, path: str) -> str | None:
    result = git("show", f"{commit}:{path}")
    return result.stdout if result.returncode == 0 else None


def merge_gates(registry_text: str) -> dict[str, dict]:
    registry = json.loads(registry_text)
    gates = {str(g.get("id")): g for g in registry.get("gates", [])}
    ids = registry.get("profiles", {}).get(PROFILE, {}).get("gates", [])
    return {str(i): gates.get(str(i), {}) for i in ids}


def load_removals(text: str | None) -> tuple[dict[str, str], list[str]]:
    """Parse the acknowledgement file into {gate: reason} and a list of problems."""
    if text is None:
        return {}, []
    problems: list[str] = []
    try:
        data = json.loads(text)
    except ValueError as exc:
        return {}, [f"{REMOVALS} is not valid JSON: {exc}"]
    entries = data.get("removals") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return {}, [f"{REMOVALS} must be an object with a removals list"]
    acknowledged: dict[str, str] = {}
    for entry in entries:
        gate = str(entry.get("gate", "")).strip() if isinstance(entry, dict) else ""
        reason = str(entry.get("reason", "")).strip() if isinstance(entry, dict) else ""
        if not gate or not reason:
            problems.append(f"{REMOVALS}: every entry needs a gate and a reason: {entry!r}")
            continue
        if gate in acknowledged:
            problems.append(f"{REMOVALS}: {gate} is listed twice")
        acknowledged[gate] = reason
    return acknowledged, problems


def judge(base_text: str, head_text: str, removals_text: str | None) -> tuple[list[str], list[str]]:
    """Compare merge profiles. Returns (failures, notes)."""
    base = merge_gates(base_text)
    head = merge_gates(head_text)
    acknowledged, failures = load_removals(removals_text)
    notes: list[str] = []
    for gate in sorted(set(base) - set(head)):
        if gate in acknowledged:
            notes.append(f"merge gate {gate} removed: {acknowledged[gate]}")
        else:
            failures.append(
                f"the base runs merge gate {gate} and this change does not; restore it, or name it in "
                f"{REMOVALS} with the reason it goes")
    for gate in sorted(set(acknowledged) & set(head)):
        failures.append(f"{REMOVALS} names {gate}, which the merge profile still runs; an acknowledgement "
                        "is for a removal in this change, not ahead of it")
    for gate in sorted(set(base) & set(head)):
        before, after = base[gate].get("command"), head[gate].get("command")
        if before != after:
            notes.append(f"merge gate {gate} changes its command: {before!r} -> {after!r}")
    for gate in sorted(set(head) - set(base)):
        notes.append(f"merge gate {gate} is new in this change")
    return failures, notes


def gated_by_merge_group() -> str:
    """The merge_group CI run scripts/ci/ci_setup.sh recorded for this pushed commit, or ""."""
    run = os.environ.get("HELM_GATED_BY_RUN", "")
    sha = os.environ.get("HELM_GATED_SHA", "")
    if os.environ.get("GITHUB_EVENT_NAME") == "push" and sha and sha == os.environ.get("GITHUB_SHA") and run.isdigit():
        return run
    return ""


def main() -> int:
    if run := gated_by_merge_group():
        print(f"gate base check: not run again; merge_group CI run {run} checked this commit against its base")
        return 0
    base, how = resolve_base()
    if base is not None and git("cat-file", "-e", f"{base}^{{commit}}").returncode != 0:
        # A shallow or partial checkout must not read as "the base has no gate".
        base, how = None, f"{how} names {base[:12]}, which is not in this checkout"
    if base is None:
        if in_ci():
            emit("error", f"gate base check: cannot read the base commit ({how})")
            return 2
        print(f"gate base check: NOT RUN ({how}); nothing to compare the merge profile against")
        return 0

    if os.environ.get(FROM_BASE_ENV) != "1":
        base_self = show(base, SELF)
        if base_self is not None and base_self != Path(__file__).read_text(encoding="utf-8"):
            print(f"gate base check: running the base commit's copy of {SELF}")
            env = dict(os.environ, **{FROM_BASE_ENV: "1", ROOT_ENV: str(ROOT)})
            return subprocess.run([sys.executable, "-I", "-", *sys.argv[1:]], input=base_self, text=True,
                                  cwd=ROOT, env=env).returncode

    base_text = show(base, REGISTRY)
    if base_text is None:
        print(f"gate base check: NOT RUN (the base {base[:12]} has no {REGISTRY})")
        return 0
    head_path = ROOT / REGISTRY
    removals_path = ROOT / REMOVALS
    failures, notes = judge(
        base_text,
        head_path.read_text(encoding="utf-8"),
        removals_path.read_text(encoding="utf-8") if removals_path.is_file() else None,
    )
    print(f"gate base check: {PROFILE} profile against base {base[:12]} ({how})")
    for note in notes:
        emit("notice" if "is new" in note else "warning", note)
    if failures:
        for failure in failures:
            emit("error", failure)
        return 1
    print("gate base check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
