#!/usr/bin/env python3
"""Validate that documentation coverage rows point at live source and docs.

This check intentionally stays lightweight so it can run in every project CI
without installing project-specific generators. It verifies the durable contracts
that broke during earlier cleanup work: active source/doc existence, public docs
manifest resolution, env-reference coverage where an env reference exists, docs
workflow wiring, and basic package/source identity.
"""
from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_NAME_RE = re.compile(r'^\s*(?:export\s+)?([A-Z][A-Z0-9_]+)\s*=')
PRIVATE_TITAN_PATTERNS = (
    '/investor/',
    '/fund',
    'credential',
    'secret',
    'runbooks/kill_switch',
    'runbooks/key_rotation',
    'runbooks/production_guide',
    'runbooks/policy_bundle_signing_ceremony',
)


def read_text(path: Path) -> str:
    return path.read_text(errors='ignore')


def parse_env_names(path: Path) -> list[str]:
    names: list[str] = []
    for line in read_text(path).splitlines():
        match = ENV_NAME_RE.match(line)
        if match:
            names.append(match.group(1))
    return sorted(set(names))


def load_manifest(path: Path) -> dict:
    return json.loads(read_text(path))


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
            text = read_text(doc)
            if any(marker in text for marker in ['TBD TBD', 'TODO TODO', 'coming soon']):
                failures.append(f'{row["canonical_doc_path"]} contains duplicated placeholder marker text')
        if source.is_dir() and (source / 'package.json').exists() and doc and doc.exists() and status == 'covered':
            package_name = ''
            try:
                package_name = json.loads((source / 'package.json').read_text()).get('name', '')
            except Exception:
                package_name = ''
            text = read_text(doc)
            if package_name and package_name not in text and source.name not in text:
                failures.append(f'{row["canonical_doc_path"]} does not mention package/source identity for {row["source_path"]}')
        if source.is_dir() and (source / 'pyproject.toml').exists() and doc and doc.exists() and status == 'covered':
            text = read_text(doc)
            if '[project]' in read_text(source / 'pyproject.toml') and 'python' not in text.lower() and 'pyproject' not in text.lower():
                failures.append(f'{row["canonical_doc_path"]} does not mention Python/pyproject identity for {row["source_path"]}')

    env_reference = ROOT / 'docs' / 'env-reference.md'
    if env_reference.exists():
        env_text = read_text(env_reference)
        for env_file in ROOT.rglob('.env.example'):
            if any(part in {'.git', 'node_modules', '.next', 'dist', 'build', 'target', '.turbo'} for part in env_file.parts):
                continue
            for name in parse_env_names(env_file):
                if name not in env_text:
                    failures.append(f'docs/env-reference.md does not mention {name} from {env_file.relative_to(ROOT)}')

    manifest_path = ROOT / 'docs' / 'public-docs.manifest.json'
    if manifest_path.exists():
        try:
            manifest = load_manifest(manifest_path)
        except Exception as exc:
            failures.append(f'docs/public-docs.manifest.json is not valid JSON: {exc}')
            manifest = {}
        repo_name = manifest.get('repo')
        if repo_name and repo_name != ROOT.name:
            failures.append(f'docs/public-docs.manifest.json repo is {repo_name!r}, expected {ROOT.name!r}')
        documents = manifest.get('documents') or manifest.get('owned_documents') or []
        slugs: set[str] = set()
        for document in documents:
            slug = str(document.get('slug', '')).strip()
            source_path = str(document.get('source_path', '')).strip()
            if not slug:
                failures.append('docs/public-docs.manifest.json has a document with blank slug')
            if slug in slugs:
                failures.append(f'docs/public-docs.manifest.json has duplicate slug: {slug}')
            slugs.add(slug)
            if not source_path:
                failures.append(f'docs/public-docs.manifest.json slug {slug} has blank source_path')
                continue
            if not (ROOT / source_path).exists():
                failures.append(f'docs/public-docs.manifest.json source does not exist for {slug}: {source_path}')
            if ROOT.name == 'titan':
                normalized = source_path.lower()
                if any(pattern in normalized for pattern in PRIVATE_TITAN_PATTERNS):
                    failures.append(f'Titan public docs manifest exposes private path for {slug}: {source_path}')

    workflows_dir = ROOT / '.github' / 'workflows'
    if workflows_dir.exists() and list(workflows_dir.glob('*.yml')):
        docs_workflow = workflows_dir / 'docs.yml'
        if not docs_workflow.exists():
            failures.append('.github/workflows/docs.yml is missing')
        elif 'docs' not in read_text(docs_workflow).lower():
            failures.append('.github/workflows/docs.yml does not appear to run documentation gates')

    if failures:
        print('Documentation truth check failed:')
        for failure in failures:
            print(f'- {failure}')
        return 1

    print(f'Documentation truth check passed: {len(rows)} coverage rows resolve to live sources and docs.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
