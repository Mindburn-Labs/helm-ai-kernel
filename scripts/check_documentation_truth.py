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

OSS_CONSOLE_CONTRADICTIONS = (
    'No bundled interactive client',
    'does not present a hosted SaaS control plane, a product UI surface',
)

OSS_SCOPE_SPEC_ONLY_PATHS = (
    'crypto/hybrid',
    'crypto/zkproof',
    'memory',
    'threatscan/ensemble',
    'evidencepack/summary',
    'skillfortify',
    'provenance',
    'budget/cost',
    'delegation/aip',
    'replay/comparison',
    'a2a/federation',
    'mcptox',
    'effects/reversibility',
    'observability/slo_engine',
    'otel/cloudevents',
    'connectors/ddipe',
)

FORBIDDEN_SOURCE_INVENTORY_PATTERNS = {'*', 'core/**', 'api/**'}
REQUIRED_RUNTIME_REFERENCE_SLUGS = {
    'helm-oss/reference/cli',
    'helm-oss/reference/http-api',
    'helm-oss/reference/execution-boundary',
}


def expected_repo_name() -> str:
    """Derive the repository name from git remote metadata.

    Release worktrees often include branch/version suffixes in the checkout
    directory. Documentation manifests should be checked against the actual
    repository identity, not the local folder name.
    """
    try:
        result = subprocess.run(
            ['git', 'config', '--get', 'remote.origin.url'],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return ROOT.name

    url = result.stdout.strip().rstrip('/')
    if not url:
        return ROOT.name
    repo = re.split(r'[:/]', url)[-1]
    if repo.endswith('.git'):
        repo = repo[:-4]
    return repo or ROOT.name


EXPECTED_REPO_NAME = expected_repo_name()


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


def git_ls_files() -> list[str]:
    result = subprocess.run(['git', 'ls-files'], cwd=ROOT, capture_output=True, text=True, check=True)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def inventory_pattern_to_regex(pattern: str) -> re.Pattern[str]:
    output = '^'
    index = 0
    while index < len(pattern):
        char = pattern[index]
        next_char = pattern[index + 1] if index + 1 < len(pattern) else ''
        if char == '*' and next_char == '*':
            output += '.*'
            index += 2
            continue
        if char == '*':
            output += '[^/]*'
        else:
            output += re.escape(char)
        index += 1
    return re.compile(f'{output}$')


def matches_inventory_pattern(file_path: str, pattern: str) -> bool:
    return bool(inventory_pattern_to_regex(pattern).match(file_path))


def matches_inventory_family(file_path: str, family: dict) -> bool:
    for pattern in family.get('exclude_patterns') or []:
        if matches_inventory_pattern(file_path, str(pattern)):
            return False
    return any(matches_inventory_pattern(file_path, str(pattern)) for pattern in family.get('source_patterns') or [])


def validate_source_inventory(failures: list[str], public_slugs: set[str]) -> None:
    manifest_path = ROOT / 'docs' / 'source-inventory.manifest.json'
    if not manifest_path.exists():
        failures.append('docs/source-inventory.manifest.json is missing')
        return

    try:
        manifest = load_manifest(manifest_path)
    except Exception as exc:
        failures.append(f'docs/source-inventory.manifest.json is not valid JSON: {exc}')
        return

    if manifest.get('schema_version') != 1:
        failures.append('docs/source-inventory.manifest.json schema_version must be 1')
    if manifest.get('repo') != EXPECTED_REPO_NAME:
        failures.append(
            f'docs/source-inventory.manifest.json repo is {manifest.get("repo")!r}, '
            f'expected {EXPECTED_REPO_NAME!r}'
        )

    inventory = manifest.get('inventory')
    if not isinstance(inventory, list) or not inventory:
        failures.append('docs/source-inventory.manifest.json inventory must be a non-empty list')
        return

    tracked = git_ls_files()
    seen_ids: set[str] = set()
    inventory_slugs: set[str] = set()
    for family in inventory:
        family_id = str(family.get('id') or '<missing-id>')
        if family_id in seen_ids:
            failures.append(f'docs/source-inventory.manifest.json has duplicate source family id: {family_id}')
        seen_ids.add(family_id)

        patterns = [str(pattern) for pattern in family.get('source_patterns') or []]
        if not patterns:
            failures.append(f'docs/source-inventory.manifest.json:{family_id} has no source_patterns')
        for pattern in patterns:
            if pattern in FORBIDDEN_SOURCE_INVENTORY_PATTERNS:
                failures.append(f'docs/source-inventory.manifest.json:{family_id} uses broad source pattern {pattern!r}')

        owner_doc = str(family.get('owner_doc_path') or '').strip()
        if owner_doc and not (ROOT / owner_doc).exists():
            failures.append(f'docs/source-inventory.manifest.json:{family_id} owner_doc_path does not exist: {owner_doc}')

        public_doc_slugs = [str(slug).strip() for slug in family.get('public_doc_slugs') or [] if str(slug).strip()]
        inventory_slugs.update(public_doc_slugs)
        for slug in public_doc_slugs:
            if (slug == 'oss' or slug.startswith('helm-oss/')) and slug not in public_slugs:
                failures.append(f'docs/source-inventory.manifest.json:{family_id} public_doc_slug is missing from public docs manifest: {slug}')

        if patterns and not any(matches_inventory_family(file_path, family) for file_path in tracked):
            failures.append(f'docs/source-inventory.manifest.json:{family_id} did not match any tracked source file')

    missing_reference_slugs = REQUIRED_RUNTIME_REFERENCE_SLUGS - inventory_slugs
    for slug in sorted(missing_reference_slugs):
        failures.append(f'docs/source-inventory.manifest.json does not link required runtime reference slug: {slug}')


def main() -> int:
    coverage = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'check_documentation_coverage.py')], cwd=ROOT)
    if coverage.returncode != 0:
        return coverage.returncode

    path = ROOT / 'docs' / 'documentation-coverage.csv'
    rows = list(csv.DictReader(path.open(newline='')))
    failures: list[str] = []
    public_slugs: set[str] = set()

    architecture = ROOT / 'docs' / 'ARCHITECTURE.md'
    if (ROOT / 'apps' / 'console').exists() and architecture.exists():
        text = read_text(architecture)
        for marker in OSS_CONSOLE_CONTRADICTIONS:
            if marker in text:
                failures.append(f'docs/ARCHITECTURE.md contradicts shipped apps/console with marker {marker!r}')

    oss_scope = ROOT / 'docs' / 'OSS_SCOPE.md'
    if oss_scope.exists():
        text = read_text(oss_scope)
        for rel_path in OSS_SCOPE_SPEC_ONLY_PATHS:
            if not (ROOT / rel_path).exists() and f'| `{rel_path}/`' in text and '✅ Active' in text:
                failures.append(f'docs/OSS_SCOPE.md marks missing path {rel_path}/ as active')

    sdk_go_mod = ROOT / 'sdk' / 'go' / 'go.mod'
    if sdk_go_mod.exists() and (ROOT / 'sdk' / 'go' / 'gen').exists():
        sdk_text = read_text(sdk_go_mod)
        for module in ('google.golang.org/grpc', 'google.golang.org/protobuf'):
            if module not in sdk_text:
                failures.append(f'sdk/go/go.mod is missing standalone generated SDK dependency {module}')

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
        if repo_name and repo_name != EXPECTED_REPO_NAME:
            failures.append(f'docs/public-docs.manifest.json repo is {repo_name!r}, expected {EXPECTED_REPO_NAME!r}')
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
            if EXPECTED_REPO_NAME == 'titan':
                normalized = source_path.lower()
                if any(pattern in normalized for pattern in PRIVATE_TITAN_PATTERNS):
                    failures.append(f'Titan public docs manifest exposes private path for {slug}: {source_path}')
        public_slugs = slugs

    validate_source_inventory(failures, public_slugs)

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
