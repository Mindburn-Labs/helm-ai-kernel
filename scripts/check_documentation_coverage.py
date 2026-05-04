#!/usr/bin/env python3
"""Validate active documentation surface coverage for this repository."""
from __future__ import annotations

import csv
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE = {'.git', 'node_modules', '.next', 'dist', 'build', 'target', 'vendor', '.turbo', '.astro', '.generated', 'bin', 'coverage', 'site', '.cache', '.venv', '__pycache__'}
CHILD_GROUPS = {'apps','services','packages','sdk','examples','infra','deploy','tools','scripts','.github','protocols','schemas','api','public','functions','configs','datasets','training','serving','eval','benchmarks','docker','tests','e2e','ops','monitoring','contracts','artifacts','proofs','reference_packs','release','fixtures','crates','cmd','integrations','modules','evidence','qa','loadtests','pipelines','packs','config','valuation','simulation','spikes'}
CONFIG_NAMES = {'Makefile','mkdocs.yml','package.json','package-lock.json','pnpm-workspace.yaml','pnpm-lock.yaml','tsconfig.json','tsconfig.base.json','tsconfig.node.json','astro.config.mjs','wrangler.jsonc','docker-compose.yml','docker-compose.dev.yml','.env.example','go.mod','Cargo.toml','pyproject.toml','ruff.toml','uv.lock','requirements.txt'}
CONFIG_SUFFIXES = ('.config.js','.config.mjs','.config.ts','.config.cjs','.config.json','.schema.json','.schema.yaml','.schema.yml')
ROUTE_EXTS = {'.astro','.ts','.tsx','.js','.jsx','.md','.mdx'}
REQUIRED_COLUMNS = [
    'project', 'surface_type', 'source_path', 'canonical_doc_path', 'audience',
    'diataxis_type', 'owner_status', 'verification_command', 'gap_status', 'reviewer_notes'
]
NON_DOC_STATUSES = {'not_applicable', 'known_gap', 'generated', 'external', 'mirror'}


def is_excluded(path: Path) -> bool:
    return any(part in EXCLUDE for part in path.parts) or any(part.startswith('.') and part not in {'.github', '.env.example'} for part in path.parts)


def rel(path: Path) -> str:
    if path == ROOT:
        return '.'
    return path.relative_to(ROOT).as_posix()


def add_if_exists(surfaces: set[str], path: Path) -> None:
    if path.exists() and not is_excluded(path.relative_to(ROOT)):
        surfaces.add(rel(path))


def discover_surfaces() -> set[str]:
    surfaces: set[str] = {'.'}
    for child in sorted(p for p in ROOT.iterdir() if p.is_dir() and not is_excluded(p.relative_to(ROOT))):
        surfaces.add(rel(child))
        if child.name in CHILD_GROUPS:
            for grandchild in sorted(p for p in child.iterdir() if p.is_dir() and not is_excluded(p.relative_to(ROOT))):
                surfaces.add(rel(grandchild))

    for current, dirs, files in os.walk(ROOT):
        current_path = Path(current)
        dirs[:] = [name for name in dirs if not is_excluded((current_path / name).relative_to(ROOT))]
        for filename in files:
            path = current_path / filename
            path_rel = path.relative_to(ROOT)
            if is_excluded(path_rel):
                continue
            source = path_rel.as_posix()
            if filename == 'README.md' or source.startswith('docs/documentation-coverage') or source.startswith('scripts/check_documentation_'):
                continue
            if filename in CONFIG_NAMES or filename.endswith(CONFIG_SUFFIXES):
                add_if_exists(surfaces, path)
            if '/.github/workflows/' in f'/{source}' and path.suffix in {'.yml', '.yaml'}:
                add_if_exists(surfaces, path)
            if '/.github/actions/' in f'/{source}' and filename in {'action.yml', 'action.yaml'}:
                add_if_exists(surfaces, path)
            if '/functions/api/' in f'/{source}' and path.suffix in {'.ts', '.js'}:
                add_if_exists(surfaces, path)
            if '/src/pages/' in f'/{source}' and path.suffix in ROUTE_EXTS:
                add_if_exists(surfaces, path)
            if '/src/app/' in f'/{source}' and filename in {'page.tsx', 'page.ts', 'route.ts', 'route.js', 'layout.tsx'}:
                add_if_exists(surfaces, path)
            if '/pages/api/' in f'/{source}' and path.suffix in {'.ts', '.js'}:
                add_if_exists(surfaces, path)
            if '/migrations/' in f'/{source}' and path.suffix in {'.sql', '.ts'}:
                add_if_exists(surfaces, path)
            if '/protocols/' in f'/{source}' and path.suffix == '.proto':
                add_if_exists(surfaces, path)
            if '/schemas/' in f'/{source}' and path.suffix in {'.json', '.yaml', '.yml'}:
                add_if_exists(surfaces, path)
            if '/api/' in f'/{source}' and path.suffix in {'.json', '.yaml', '.yml'}:
                add_if_exists(surfaces, path)
            if source.startswith('public/') and (filename in {'llms.txt', 'llms-full.txt', 'robots.txt', '_headers', '_redirects', '_routes.json', 'site.webmanifest'} or source.startswith('public/security/')):
                add_if_exists(surfaces, path)
            if '/src/data/' in f'/{source}' and path.suffix in {'.ts', '.js', '.json'}:
                add_if_exists(surfaces, path)
            if source == 'src/content.config.ts':
                add_if_exists(surfaces, path)
    return surfaces


def load_rows() -> list[dict[str, str]]:
    path = ROOT / 'docs' / 'documentation-coverage.csv'
    if not path.exists():
        raise SystemExit(f'missing coverage ledger: {path.relative_to(ROOT)}')
    with path.open(newline='') as fh:
        reader = csv.DictReader(fh)
        missing = [col for col in REQUIRED_COLUMNS if col not in (reader.fieldnames or [])]
        if missing:
            raise SystemExit(f'coverage ledger missing columns: {", ".join(missing)}')
        return list(reader)


def main() -> int:
    rows = load_rows()
    by_source = {row['source_path']: row for row in rows}
    discovered = discover_surfaces()
    failures: list[str] = []

    for source in sorted(discovered):
        if source not in by_source:
            failures.append(f'missing coverage row for active surface: {source}')

    for row in rows:
        source = row['source_path']
        source_path = ROOT if source == '.' else ROOT / source
        if not source_path.exists():
            failures.append(f'coverage source does not exist: {source}')

        gap_status = row['gap_status'].strip().lower()
        if not gap_status:
            failures.append(f'blank gap_status for {source}')
        if gap_status in {'gap', 'missing', 'undocumented'}:
            failures.append(f'unresolved documentation gap for {source}')

        owner_status = row['owner_status'].strip()
        if not owner_status:
            failures.append(f'blank owner_status for {source}')
        if any(marker in owner_status.upper() for marker in ['TODO', 'TBD']):
            failures.append(f'owner_status must not be naked TODO/TBD for {source}')

        doc = row['canonical_doc_path'].strip()
        if gap_status not in NON_DOC_STATUSES:
            if not doc:
                failures.append(f'missing canonical_doc_path for {source}')
            elif not (ROOT / doc).exists():
                failures.append(f'canonical doc does not exist for {source}: {doc}')
        if gap_status == 'known_gap' and 'known gap' not in row['reviewer_notes'].lower():
            failures.append(f'known gap row must say "known gap" in reviewer_notes: {source}')

    if failures:
        print('Documentation coverage check failed:')
        for failure in failures:
            print(f'- {failure}')
        return 1

    print(f'Documentation coverage check passed: {len(rows)} rows cover {len(discovered)} active surfaces.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
