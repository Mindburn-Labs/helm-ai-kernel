#!/usr/bin/env python3
"""Validate that documentation coverage rows point at live source and docs.

Check public manifests, package identity, environment references, and the
documentation checks required by CI. The checker uses the standard library.
"""
from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
from pathlib import Path

from check_documentation_manifests import read_text, validate_manifests

ROOT = Path(__file__).resolve().parents[1]
ENV_NAME_RE = re.compile(r'^\s*(?:export\s+)?([A-Z][A-Z0-9_]+)\s*=')

OSS_CONSOLE_CONTRADICTIONS = (
    'No bundled interactive client',
    'does not present a hosted SaaS control plane, a product UI surface',
)

KERNEL_SCOPE_SPEC_ONLY_PATHS = (
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

CANONICAL_REPO_RENAMES = {
    'helm' + '-oss': 'helm-ai-kernel',
}
CANONICAL_HOMEBREW_INSTALL = 'brew install mindburn-labs/tap/helm-ai-kernel'
BROKEN_HOMEBREW_INSTALL_RE = re.compile(
    r'brew\s+install\s+(?:helm-ai-kernel|mindburnlabs/tap/helm-ai-kernel)(?![\w-])',
    re.IGNORECASE,
)


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
        return CANONICAL_REPO_RENAMES.get(ROOT.name, ROOT.name)

    url = result.stdout.strip().rstrip('/')
    if not url:
        return CANONICAL_REPO_RENAMES.get(ROOT.name, ROOT.name)
    repo = re.split(r'[:/]', url)[-1]
    if repo.endswith('.git'):
        repo = repo[:-4]
    repo = repo or ROOT.name
    return CANONICAL_REPO_RENAMES.get(repo, repo)


EXPECTED_REPO_NAME = expected_repo_name()


def parse_env_names(path: Path) -> list[str]:
    names: list[str] = []
    for line in read_text(path).splitlines():
        match = ENV_NAME_RE.match(line)
        if match:
            names.append(match.group(1))
    return sorted(set(names))


def validate_sdk_freshness_docs(failures: list[str]) -> None:
    version_path = ROOT / 'VERSION'
    if not version_path.exists():
        failures.append('VERSION is missing; SDK freshness docs cannot be checked')
        return
    version = read_text(version_path).strip()
    java_coordinate = f'io.github.mindburnlabs:helm-sdk:{version}'

    docs_to_scan = [
        ROOT / 'docs' / 'DEVELOPER_JOURNEY.md',
        ROOT / 'docs' / 'sdks' / '00_INDEX.md',
        ROOT / 'docs' / 'EXAMPLES.md',
    ]
    stale_patterns = [
        (re.compile(r'source manifest currently declares `0\.5\.1`'), 'stale SDK source manifest version'),
        (re.compile(r'io\.github\.mindburnlabs:helm-sdk:0\.5\.2(?![0-9])'), 'stale Java Maven coordinate'),
        (re.compile(r'artifact is source-backed but not registry-backed'), 'contradictory Java registry status'),
        (re.compile(r'avoid claiming Maven Central availability'), 'contradictory Java Maven Central guidance'),
    ]
    sdk_version_claims = [
        (
            'Java Maven coordinate',
            re.compile(r'io\.github\.mindburnlabs:helm-sdk:(?P<version>[0-9]+\.[0-9]+\.[0-9]+)'),
        ),
        (
            'Java Maven dependency',
            re.compile(
                r'<groupId>io\.github\.mindburnlabs</groupId>\s*'
                r'<artifactId>helm-sdk</artifactId>\s*'
                r'<version>(?P<version>[0-9]+\.[0-9]+\.[0-9]+)</version>',
                re.MULTILINE,
            ),
        ),
        (
            'Python pinned install',
            re.compile(r'helm-sdk(?:==|~=|>=|<=|=)(?P<version>[0-9]+\.[0-9]+\.[0-9]+)'),
        ),
        (
            'npm pinned install',
            re.compile(r'@mindburn/helm-ai-kernel@(?P<version>[0-9]+\.[0-9]+\.[0-9]+)'),
        ),
        (
            'Cargo pinned dependency',
            re.compile(r'helm-sdk\s*=\s*"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"'),
        ),
    ]
    for path in docs_to_scan:
        if not path.exists():
            failures.append(f'{path.relative_to(ROOT)} is missing from SDK freshness docs check')
            continue
        text = read_text(path)
        for pattern, detail in stale_patterns:
            match = pattern.search(text)
            if match:
                failures.append(f'{path.relative_to(ROOT)} contains {detail}: {match.group(0)!r}')
        for claim_name, claim_pattern in sdk_version_claims:
            for match in claim_pattern.finditer(text):
                found_version = match.group('version')
                if found_version != version:
                    failures.append(
                        f'{path.relative_to(ROOT)} contains stale {claim_name}: '
                        f'{found_version} != {version}'
                    )

    developer_journey = ROOT / 'docs' / 'DEVELOPER_JOURNEY.md'
    sdk_index = ROOT / 'docs' / 'sdks' / '00_INDEX.md'
    examples = ROOT / 'docs' / 'EXAMPLES.md'

    if developer_journey.exists() and java_coordinate not in read_text(developer_journey):
        failures.append(f'docs/DEVELOPER_JOURNEY.md is missing current Java coordinate {java_coordinate}')
    if sdk_index.exists():
        sdk_text = read_text(sdk_index)
        if java_coordinate not in sdk_text:
            failures.append(f'docs/sdks/00_INDEX.md is missing current Java coordinate {java_coordinate}')
        if 'version-status.json' not in sdk_text and 'make version-drift-published' not in sdk_text:
            failures.append('docs/sdks/00_INDEX.md must point pinned install claims at version-status.json or make version-drift-published')
    if examples.exists() and java_coordinate not in read_text(examples):
        failures.append(f'docs/EXAMPLES.md is missing current Java coordinate {java_coordinate}')


def validate_homebrew_install_docs(failures: list[str]) -> None:
    """Keep active public install guidance on the canonical tap coordinate."""
    active_docs = [ROOT / 'README.md', *sorted((ROOT / 'docs').rglob('*.md'))]
    for path in active_docs:
        if not path.exists():
            failures.append(f'{path.relative_to(ROOT)} is missing from active installation docs check')
            continue
        text = read_text(path)
        match = BROKEN_HOMEBREW_INSTALL_RE.search(text)
        if match:
            failures.append(
                f'{path.relative_to(ROOT)} contains a non-canonical Homebrew install: {match.group(0)!r}'
            )

    for path in (ROOT / 'README.md', ROOT / 'docs' / 'QUICKSTART.md'):
        if path.exists() and CANONICAL_HOMEBREW_INSTALL not in read_text(path):
            failures.append(f'{path.relative_to(ROOT)} is missing canonical Homebrew install {CANONICAL_HOMEBREW_INSTALL!r}')


def main() -> int:
    coverage = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'check_documentation_coverage.py')], cwd=ROOT)
    if coverage.returncode != 0:
        return coverage.returncode

    path = ROOT / 'docs' / 'documentation-coverage.csv'
    rows = list(csv.DictReader(path.open(newline='')))
    failures: list[str] = []

    architecture = ROOT / 'docs' / 'ARCHITECTURE.md'
    if (ROOT / 'apps' / 'console').exists() and architecture.exists():
        text = read_text(architecture)
        for marker in OSS_CONSOLE_CONTRADICTIONS:
            if marker in text:
                failures.append(f'docs/ARCHITECTURE.md contradicts a shipped browser UI with marker {marker!r}')
    elif architecture.exists():
        text = read_text(architecture)
        for marker in ('does not include Console source code', 'headless kernel and API'):
            if marker not in text:
                failures.append(f'docs/ARCHITECTURE.md is missing headless browser-split marker {marker!r}')

    kernel_scope = ROOT / 'docs' / 'KERNEL_SCOPE.md'
    if kernel_scope.exists():
        text = read_text(kernel_scope)
        for rel_path in KERNEL_SCOPE_SPEC_ONLY_PATHS:
            if not (ROOT / rel_path).exists() and f'| `{rel_path}/`' in text and '✅ Active' in text:
                failures.append(f'docs/KERNEL_SCOPE.md marks missing path {rel_path}/ as active')

    sdk_go_mod = ROOT / 'sdk' / 'go' / 'go.mod'
    if sdk_go_mod.exists() and (ROOT / 'sdk' / 'go' / 'gen').exists():
        sdk_text = read_text(sdk_go_mod)
        for module in ('google.golang.org/grpc', 'google.golang.org/protobuf'):
            if module not in sdk_text:
                failures.append(f'sdk/go/go.mod is missing standalone generated SDK dependency {module}')

    validate_sdk_freshness_docs(failures)
    validate_homebrew_install_docs(failures)

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

    validate_manifests(ROOT, EXPECTED_REPO_NAME, failures)

    # CI runs the documentation gates through `make check`, which runs the
    # merge profile of scripts/ci/quality-gates.json (`ci / gate`).
    workflows_dir = ROOT / '.github' / 'workflows'
    if workflows_dir.exists() and list(workflows_dir.glob('*.yml')):
        ci_workflow = workflows_dir / 'ci.yml'
        if not ci_workflow.exists():
            failures.append('.github/workflows/ci.yml is missing')
        registry_path = ROOT / 'scripts' / 'ci' / 'quality-gates.json'
        merge_gates = json.loads(read_text(registry_path)).get('profiles', {}).get('merge', {}).get('gates', []) if registry_path.exists() else []
        for gate_id in ('docs-truth', 'docs-openapi-parity'):
            if gate_id not in merge_gates:
                failures.append(f'the merge quality profile (make check) does not run {gate_id}')

    if failures:
        print('Documentation truth check failed:')
        for failure in failures:
            print(f'- {failure}')
        return 1

    print(f'Documentation truth check passed: {len(rows)} coverage rows resolve to live sources and docs.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
