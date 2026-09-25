#!/usr/bin/env python3
"""Hold the Postgres-gated proofs to "ran and passed", never "skipped" (T-12).

  check_postgres_proofs.py discover CORE_DIR MANIFEST
      every Test* in CORE_DIR that reads HELM_TEST_POSTGRES_URL must be in
      MANIFEST, and every MANIFEST entry must still exist
  check_postgres_proofs.py verify MANIFEST LOG
      LOG (go test -v output) must show each listed test passing exactly its
      count, with no skip and no failure
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

TEST_FUNC = re.compile(r"^func (Test\w+)\(", re.MULTILINE)
GATE = 'Getenv("HELM_TEST_POSTGRES_URL")'
RESULT = re.compile(r"^(\s*)--- (PASS|FAIL|SKIP): (\S+)", re.MULTILINE)
MODES = ("race", "plain")


def parse_manifest(text: str) -> dict[tuple[str, str], int]:
    entries: dict[tuple[str, str], int] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        fields = raw.split("#", 1)[0].split()
        if not fields:
            continue
        if len(fields) != 4 or not fields[2].isdigit() or int(fields[2]) < 1 or fields[3] not in MODES:
            raise SystemExit(f"manifest line {number}: want '<package> <test> <count> <race|plain>', got {raw!r}")
        entries[(fields[0], fields[1])] = int(fields[2])
    if not entries:
        raise SystemExit("manifest lists no proofs")
    return entries


FUNC = re.compile(r"^func (\w+)\(", re.MULTILINE)


def discover(core: Path) -> set[tuple[str, str]]:
    """Tests that skip without HELM_TEST_POSTGRES_URL: they read it themselves
    or call a helper (in the same package's test files) that does."""
    found = set()
    by_package: dict[Path, list[str]] = {}
    for path in core.rglob("*_test.go"):
        by_package.setdefault(path.parent, []).append(path.read_text(encoding="utf-8"))
    for package, texts in by_package.items():
        if not any(GATE in text for text in texts):
            continue
        bodies: dict[str, str] = {}
        for text in texts:
            funcs = list(FUNC.finditer(text))
            for i, match in enumerate(funcs):
                end = funcs[i + 1].start() if i + 1 < len(funcs) else len(text)
                bodies[match.group(1)] = text[match.start():end]
        gated = {name for name, body in bodies.items() if GATE in body}
        grew = True
        while grew:
            grew = False
            for name, body in bodies.items():
                if name not in gated and any(re.search(rf"\b{re.escape(h)}\(", body) for h in gated):
                    gated.add(name)
                    grew = True
        for name in gated:
            if name.startswith("Test"):
                found.add((package.relative_to(core).as_posix(), name))
    return found


def verify(manifest: dict[tuple[str, str], int], log: str) -> list[str]:
    counts: dict[str, Counter[str]] = {}
    for indent, status, name in RESULT.findall(log):
        # A run passes when its top-level line says so; a failed or skipped
        # subtest counts against its test.
        if status == "PASS" and indent:
            continue
        counts.setdefault(name.split("/", 1)[0], Counter())[status] += 1
    problems = []
    for (package, test), want in sorted(manifest.items()):
        got = counts.get(test, Counter())
        if got["SKIP"]:
            problems.append(f"{package} {test}: skipped {got['SKIP']} time(s); a skipped proof is not a pass")
        if got["FAIL"]:
            problems.append(f"{package} {test}: failed {got['FAIL']} time(s)")
        if got["PASS"] != want:
            problems.append(f"{package} {test}: passed {got['PASS']} of {want} run(s)")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "discover":
        manifest = parse_manifest(Path(argv[3]).read_text(encoding="utf-8"))
        found = discover(Path(argv[2]))
        unlisted = sorted(found - set(manifest))
        missing = sorted(set(manifest) - found)
        for package, test in unlisted:
            print(f"::error::{package} {test} skips without HELM_TEST_POSTGRES_URL but is not in {argv[3]}")
        for package, test in missing:
            print(f"::error::{argv[3]} lists {package} {test}, which no longer reads HELM_TEST_POSTGRES_URL; remove it")
        print(f"postgres proofs: {len(found)} gated test(s) found, {len(manifest)} listed")
        return 1 if unlisted or missing else 0
    if len(argv) == 4 and argv[1] == "verify":
        manifest = parse_manifest(Path(argv[2]).read_text(encoding="utf-8"))
        problems = verify(manifest, Path(argv[3]).read_text(encoding="utf-8", errors="replace"))
        for problem in problems:
            print(f"::error::{problem}")
        runs = sum(manifest.values())
        print(f"postgres proofs: {len(manifest)} test(s), {runs} run(s) required, {len(problems)} problem(s)")
        return 1 if problems else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
