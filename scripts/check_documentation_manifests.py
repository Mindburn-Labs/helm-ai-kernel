"""Validate public documentation and source inventory manifests."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

FORBIDDEN_SOURCE_INVENTORY_PATTERNS = {'*', 'core/**', 'api/**'}
REQUIRED_RUNTIME_REFERENCE_SLUGS = {
    'reference/cli',
    'reference/http-api',
    'how-helm-works',
}
CANONICAL_PUBLIC_OPENAPI_PATH = 'api/openapi/helm.openapi.yaml'
PUBLIC_HTTP_API_SLUG = 'reference/http-api'
PUBLIC_HTTP_API_SOURCE_PATH = 'docs/reference/http-api.md'
SHA256_DIGEST_RE = re.compile(r'^sha256:[0-9a-f]{64}$')
GIT_BLOB_SHA1_RE = re.compile(r'^[0-9a-f]{40}$')
OPENAPI_EXAMPLE_SOURCE_TEST_RE = re.compile(
    r'^\s*source_test:\s*["\']?([^"\'\s]+#[A-Za-z_][A-Za-z0-9_]*)["\']?\s*$',
    re.MULTILINE,
)
PUBLIC_DOC_TAXONOMY_VOCABULARIES = {
    'category': 'categories',
    'task': 'tasks',
    'audience': 'audiences',
    'publication_status': 'publication_statuses',
    'runtime_scope': 'runtime_scopes',
}
REQUIRED_PUBLIC_DOC_METADATA = (
    'category',
    'tasks',
    'audiences',
    'publication_status',
    'runtime_scope',
    'inbound_human_path',
)


def read_text(path: Path) -> str:
    return path.read_text(errors='ignore')


def load_manifest(path: Path) -> dict:
    return json.loads(read_text(path))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            digest.update(chunk)
    return 'sha256:' + digest.hexdigest()


def git_blob_sha1(root: Path, path: str) -> str | None:
    result = subprocess.run(
        ['git', 'rev-parse', '--verify', f'HEAD:{path}'],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def git_ls_files(root: Path) -> list[str]:
    result = subprocess.run(['git', 'ls-files'], cwd=root, capture_output=True, text=True, check=True)
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


def validate_source_inventory(root: Path, expected_repo: str, failures: list[str], public_slugs: set[str]) -> None:
    manifest_path = root / 'docs' / 'source-inventory.manifest.json'
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
    if manifest.get('repo') != expected_repo:
        failures.append(
            f'docs/source-inventory.manifest.json repo is {manifest.get("repo")!r}, '
            f'expected {expected_repo!r}'
        )

    inventory = manifest.get('inventory')
    if not isinstance(inventory, list) or not inventory:
        failures.append('docs/source-inventory.manifest.json inventory must be a non-empty list')
        return

    tracked = git_ls_files(root)
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
        if owner_doc and not (root / owner_doc).exists():
            failures.append(f'docs/source-inventory.manifest.json:{family_id} owner_doc_path does not exist: {owner_doc}')

        public_doc_slugs = [str(slug).strip() for slug in family.get('public_doc_slugs') or [] if str(slug).strip()]
        inventory_slugs.update(public_doc_slugs)
        for slug in public_doc_slugs:
            if slug not in public_slugs:
                failures.append(f'docs/source-inventory.manifest.json:{family_id} public_doc_slug is missing from public docs manifest: {slug}')

        if patterns and not any(matches_inventory_family(file_path, family) for file_path in tracked):
            failures.append(f'docs/source-inventory.manifest.json:{family_id} did not match any tracked source file')

    missing_reference_slugs = REQUIRED_RUNTIME_REFERENCE_SLUGS - inventory_slugs
    for slug in sorted(missing_reference_slugs):
        failures.append(f'docs/source-inventory.manifest.json does not link required runtime reference slug: {slug}')


def validate_public_api_contract(root: Path, failures: list[str], manifest: dict) -> None:
    contract = manifest.get('api_contract')
    if not isinstance(contract, dict):
        failures.append('docs/public-docs.manifest.json api_contract is missing')
        return
    if contract.get('schema_version') != 1:
        failures.append('docs/public-docs.manifest.json api_contract schema_version must be 1')

    source_path = contract.get('source_path')
    if source_path != CANONICAL_PUBLIC_OPENAPI_PATH:
        failures.append(
            'docs/public-docs.manifest.json api_contract source_path must be '
            f'{CANONICAL_PUBLIC_OPENAPI_PATH!r}, got {source_path!r}'
        )
        return
    source = root / source_path
    if not source.exists():
        failures.append(f'docs/public-docs.manifest.json api_contract source does not exist: {source_path}')
        return

    openapi_text = read_text(source)
    for source_test_ref in OPENAPI_EXAMPLE_SOURCE_TEST_RE.findall(openapi_text):
        source_test_path, test_name = source_test_ref.split('#', 1)
        test_file = root / source_test_path
        if not test_file.is_file():
            failures.append(
                f'OpenAPI docs example source_test file does not exist: {source_test_ref}'
            )
            continue
        test_text = read_text(test_file)
        if not re.search(rf'^func\s+{re.escape(test_name)}\s*\(', test_text, re.MULTILINE):
            failures.append(
                f'OpenAPI docs example source_test symbol does not exist: {source_test_ref}'
            )

    content_sha256 = str(contract.get('content_sha256') or '')
    if not SHA256_DIGEST_RE.fullmatch(content_sha256):
        failures.append('docs/public-docs.manifest.json api_contract content_sha256 must be sha256:<64 lowercase hex>')
    elif actual := sha256_file(source):
        if content_sha256 != actual:
            failures.append(
                'docs/public-docs.manifest.json api_contract content_sha256 does not match '
                f'{source_path}: {content_sha256} != {actual}'
            )

    git_blob = str(contract.get('git_blob_sha1') or '')
    if not GIT_BLOB_SHA1_RE.fullmatch(git_blob):
        failures.append('docs/public-docs.manifest.json api_contract git_blob_sha1 must be 40 lowercase hex')
    else:
        actual_blob = git_blob_sha1(root, source_path)
        if actual_blob is None:
            failures.append(f'cannot resolve git blob for public OpenAPI source: {source_path}')
        elif git_blob != actual_blob:
            failures.append(
                'docs/public-docs.manifest.json api_contract git_blob_sha1 does not match '
                f'{source_path}: {git_blob} != {actual_blob}'
            )

    documents = manifest.get('documents')
    if documents is None:
        documents = manifest.get('owned_documents')
    if documents is None:
        documents = []
    http_api_docs = [document for document in documents if document.get('slug') == PUBLIC_HTTP_API_SLUG]
    if len(http_api_docs) != 1:
        failures.append(f'docs/public-docs.manifest.json must define exactly one {PUBLIC_HTTP_API_SLUG!r} document')
        return
    if http_api_docs[0].get('source_path') != PUBLIC_HTTP_API_SOURCE_PATH:
        failures.append(
            f'docs/public-docs.manifest.json {PUBLIC_HTTP_API_SLUG} source_path must be '
            f'{PUBLIC_HTTP_API_SOURCE_PATH!r}'
        )
        return

    http_api_source = root / PUBLIC_HTTP_API_SOURCE_PATH
    if not http_api_source.exists():
        failures.append(f'{PUBLIC_HTTP_API_SOURCE_PATH} is missing')
        return
    http_api_text = read_text(http_api_source)

    operations = contract.get('public_operations')
    if not isinstance(operations, list) or not operations:
        failures.append('docs/public-docs.manifest.json api_contract public_operations must be a non-empty list')
        return
    seen_routes: set[str] = set()
    seen_operation_ids: set[str] = set()
    for operation in operations:
        if not isinstance(operation, dict):
            failures.append('docs/public-docs.manifest.json api_contract public_operations must contain objects')
            continue
        method = str(operation.get('method') or '').strip()
        path = str(operation.get('path') or '').strip()
        operation_id = str(operation.get('operation_id') or '').strip()
        route = f'{method} {path}'
        if method not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'} or not path.startswith('/') or not operation_id:
            failures.append(f'docs/public-docs.manifest.json api_contract has invalid public operation: {operation!r}')
            continue
        if route in seen_routes:
            failures.append(f'docs/public-docs.manifest.json api_contract has duplicate public route: {route}')
        seen_routes.add(route)
        if operation_id in seen_operation_ids:
            failures.append(f'docs/public-docs.manifest.json api_contract has duplicate operation_id: {operation_id}')
        seen_operation_ids.add(operation_id)
        if route not in http_api_text:
            failures.append(
                f'{PUBLIC_HTTP_API_SOURCE_PATH} does not list public API contract route {route} '
                'from docs/public-docs.manifest.json'
            )


def validate_public_docs_taxonomy(failures: list[str], manifest: dict, documents: list[dict]) -> None:
    taxonomy = manifest.get('taxonomy')
    if not isinstance(taxonomy, dict):
        failures.append('docs/public-docs.manifest.json taxonomy is missing')
        return
    if taxonomy.get('schema_version') != 1:
        failures.append('docs/public-docs.manifest.json taxonomy schema_version must be 1')

    metadata = taxonomy.get('document_metadata')
    if not isinstance(metadata, dict):
        failures.append('docs/public-docs.manifest.json taxonomy document_metadata is missing')
    else:
        for field in REQUIRED_PUBLIC_DOC_METADATA:
            if not isinstance(metadata.get(field), str) or not metadata[field].strip():
                failures.append(
                    'docs/public-docs.manifest.json taxonomy document_metadata '
                    f'must document {field}'
                )

    vocabularies: dict[str, set[str]] = {}
    for field, taxonomy_key in PUBLIC_DOC_TAXONOMY_VOCABULARIES.items():
        entries = taxonomy.get(taxonomy_key)
        if not isinstance(entries, list) or not entries:
            failures.append(
                f'docs/public-docs.manifest.json taxonomy {taxonomy_key} must be a non-empty list'
            )
            vocabularies[field] = set()
            continue
        ids: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                failures.append(
                    f'docs/public-docs.manifest.json taxonomy {taxonomy_key} entries must be objects'
                )
                continue
            identifier = str(entry.get('id') or '').strip()
            label = str(entry.get('label') or '').strip()
            description = str(entry.get('description') or '').strip()
            if not identifier or not label or not description:
                failures.append(
                    f'docs/public-docs.manifest.json taxonomy {taxonomy_key} entries need id, label, and description'
                )
                continue
            if identifier in ids:
                failures.append(
                    f'docs/public-docs.manifest.json taxonomy {taxonomy_key} has duplicate id: {identifier}'
                )
            ids.add(identifier)
        vocabularies[field] = ids

    slugs = {str(document.get('slug') or '').strip() for document in documents}
    for document in documents:
        slug = str(document.get('slug') or '').strip() or '<blank-slug>'
        category = document.get('category')
        if not isinstance(category, str) or category not in vocabularies['category']:
            failures.append(
                f'docs/public-docs.manifest.json slug {slug} must set category from taxonomy categories'
            )

        for field, vocabulary_field in (('tasks', 'task'), ('audiences', 'audience')):
            values = document.get(field)
            if not isinstance(values, list) or not values:
                failures.append(
                    f'docs/public-docs.manifest.json slug {slug} must set non-empty {field}'
                )
                continue
            if not all(isinstance(value, str) and value for value in values):
                failures.append(
                    f'docs/public-docs.manifest.json slug {slug} {field} must contain non-empty strings'
                )
                continue
            if len(values) != len(set(values)):
                failures.append(
                    f'docs/public-docs.manifest.json slug {slug} has duplicate {field}'
                )
            for value in values:
                if value not in vocabularies[vocabulary_field]:
                    failures.append(
                        f'docs/public-docs.manifest.json slug {slug} has unknown {field} value: {value!r}'
                    )

        for field in ('publication_status', 'runtime_scope'):
            value = document.get(field)
            if not isinstance(value, str) or value not in vocabularies[field]:
                failures.append(
                    f'docs/public-docs.manifest.json slug {slug} must set {field} from taxonomy'
                )

        path = document.get('inbound_human_path')
        if not isinstance(path, list) or not path or not all(isinstance(part, str) and part for part in path):
            failures.append(
                f'docs/public-docs.manifest.json slug {slug} must set non-empty inbound_human_path'
            )
            continue
        if len(path) != len(set(path)):
            failures.append(
                f'docs/public-docs.manifest.json slug {slug} inbound_human_path has duplicate slugs'
            )
        if path[0] != 'index':
            failures.append(
                f'docs/public-docs.manifest.json slug {slug} inbound_human_path must start at index'
            )
        if path[-1] != slug:
            failures.append(
                f'docs/public-docs.manifest.json slug {slug} inbound_human_path must end at its slug'
            )
        for path_slug in path:
            if path_slug not in slugs:
                failures.append(
                    f'docs/public-docs.manifest.json slug {slug} inbound_human_path references unknown slug: {path_slug}'
                )


def validate_manifests(root: Path, expected_repo: str, failures: list[str]) -> None:
    public_slugs: set[str] = set()
    manifest_path = root / 'docs' / 'public-docs.manifest.json'
    if manifest_path.exists():
        try:
            manifest = load_manifest(manifest_path)
        except Exception as exc:
            failures.append(f'docs/public-docs.manifest.json is not valid JSON: {exc}')
            manifest = {}
        repo_name = manifest.get('repo')
        if repo_name and repo_name != expected_repo:
            failures.append(f'docs/public-docs.manifest.json repo is {repo_name!r}, expected {expected_repo!r}')
        documents = manifest.get('documents')
        if documents is None:
            documents = manifest.get('owned_documents')
        if documents is None:
            documents = []
        for document in documents:
            slug = str(document.get('slug', '')).strip()
            source_path = str(document.get('source_path', '')).strip()
            if not slug:
                failures.append('docs/public-docs.manifest.json has a document with blank slug')
            if slug in public_slugs:
                failures.append(f'docs/public-docs.manifest.json has duplicate slug: {slug}')
            public_slugs.add(slug)
            if not source_path:
                failures.append(f'docs/public-docs.manifest.json slug {slug} has blank source_path')
                continue
            if not (root / source_path).exists():
                failures.append(f'docs/public-docs.manifest.json source does not exist for {slug}: {source_path}')
        validate_public_docs_taxonomy(failures, manifest, documents)
        validate_public_api_contract(root, failures, manifest)

    validate_source_inventory(root, expected_repo, failures, public_slugs)
