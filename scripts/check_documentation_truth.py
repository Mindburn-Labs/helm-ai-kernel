#!/usr/bin/env python3
"""Validate that documentation coverage rows point at live source and docs."""
from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    coverage = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'check_documentation_coverage.py')], cwd=ROOT)
    if coverage.returncode != 0:
        return coverage.returncode

    path = ROOT / 'docs' / 'documentation-coverage.csv'
    rows = list(csv.DictReader(path.open(newline='')))
    failures: list[str] = []

    for row in rows:
        source = ROOT if row['source_path'] == '.' else ROOT / row['source_path']
        doc = ROOT / row['canonical_doc_path'] if row['canonical_doc_path'] else None
        status = row['gap_status'].strip().lower()
        if doc and doc.exists() and status == 'covered':
            text = doc.read_text(errors='ignore')
            if any(marker in text for marker in ['TBD TBD', 'TODO TODO']):
                failures.append(f'{row["canonical_doc_path"]} contains duplicated placeholder marker text')
        if source.is_dir() and (source / 'package.json').exists() and doc and doc.exists() and status == 'covered':
            package_name = ''
            try:
                import json
                package_name = json.loads((source / 'package.json').read_text()).get('name', '')
            except Exception:
                package_name = ''
            text = doc.read_text(errors='ignore')
            if package_name and package_name not in text and source.name not in text:
                failures.append(f'{row["canonical_doc_path"]} does not mention package/source identity for {row["source_path"]}')
        if source.is_dir() and (source / 'pyproject.toml').exists() and doc and doc.exists() and status == 'covered':
            text = doc.read_text(errors='ignore')
            if '[project]' in (source / 'pyproject.toml').read_text(errors='ignore') and 'python' not in text.lower() and 'pyproject' not in text.lower():
                failures.append(f'{row["canonical_doc_path"]} does not mention Python/pyproject identity for {row["source_path"]}')

    if failures:
        print('Documentation truth check failed:')
        for failure in failures:
            print(f'- {failure}')
        return 1

    print(f'Documentation truth check passed: {len(rows)} coverage rows resolve to live sources and docs.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
