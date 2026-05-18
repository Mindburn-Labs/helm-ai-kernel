#!/usr/bin/env python3
"""Normalize Scorecard SARIF categories for pull request code scanning.

Scorecard emits a branch-protection SARIF category on default-branch runs, but
not on pull request merge refs. GitHub compares PR analyses by category, so the
missing empty category produces a "configuration not found" warning even though
branch protection is repository policy rather than PR-owned code.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
from pathlib import Path


BRANCH_PROTECTION_PREFIX = "supply-chain/branch-protection/"
ONLINE_SCM_PREFIX = "supply-chain/online-scm/"
LOCAL_PREFIX = "supply-chain/local/"


def automation_id(run: dict) -> str:
    details = run.get("automationDetails")
    if not isinstance(details, dict):
        return ""
    value = details.get("id")
    return value if isinstance(value, str) else ""


def suffix_from(category_id: str) -> str:
    parts = category_id.split("/", 2)
    if len(parts) == 3 and parts[2]:
        return parts[2]
    return "normalized"


def normalize(path: Path) -> bool:
    payload = json.loads(path.read_text(encoding="utf-8"))
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise SystemExit(f"{path}: SARIF payload has no runs array")

    if any(automation_id(run).startswith(BRANCH_PROTECTION_PREFIX) for run in runs):
        return False

    template = next((run for run in runs if automation_id(run).startswith(ONLINE_SCM_PREFIX)), None)
    if template is None:
        template = next((run for run in runs if automation_id(run).startswith(LOCAL_PREFIX)), None)
    if template is None and runs:
        template = runs[0]
    if template is None:
        raise SystemExit(f"{path}: cannot add branch-protection category to empty SARIF")

    injected = copy.deepcopy(template)
    category_suffix = suffix_from(automation_id(template))
    injected["automationDetails"] = {"id": BRANCH_PROTECTION_PREFIX + category_suffix}
    injected["results"] = []
    driver = injected.get("tool", {}).get("driver")
    if isinstance(driver, dict):
        driver["rules"] = []
    runs.append(injected)

    normalized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as fh:
        tmp_name = fh.name
        fh.write(normalized)
    os.replace(tmp_name, path)
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: normalize_scorecard_sarif.py SARIF_PATH", file=sys.stderr)
        return 2
    changed = normalize(Path(sys.argv[1]))
    if changed:
        print("added empty supply-chain/branch-protection SARIF category")
    else:
        print("supply-chain/branch-protection SARIF category already present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
