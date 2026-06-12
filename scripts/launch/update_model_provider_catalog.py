#!/usr/bin/env python3
"""Validate and normalize the Launchpad BYO model provider catalog.

This script is intentionally conservative: provider inclusion is sourced from
official provider documentation, while scheduled runs keep the catalog
normalized and check whether the documentation sources are still reachable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "core/pkg/launchpad/modelproviders/catalog.json"
SOURCE_FINGERPRINTS = ROOT / "core/pkg/launchpad/modelproviders/source_fingerprints.json"
HELPER = ROOT / "tools/launchpad/artifacts/model-gateway-check.sh"
SCHEMA_VERSION = "helm.launchpad.model_providers.v1"
FINGERPRINT_SCHEMA_VERSION = "helm.launchpad.model_provider_source_fingerprints.v1"
VALID_REGIONS = {"US", "EU", "CN"}
USER_AGENT = "helm-ai-kernel-model-provider-catalog/1.0"


def load_catalog(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def normalize_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"only absolute HTTPS URLs are allowed: {value!r}")
    path = parsed.path.rstrip("/")
    return f"https://{parsed.netloc.lower()}{path}"


def destination(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme == "https" and parsed.netloc:
        host = parsed.netloc.lower()
        return host if ":" in host else f"{host}:443"
    if "://" in value:
        raise ValueError(f"unsupported URL: {value!r}")
    host = value.strip().lower()
    return host if ":" in host else f"{host}:443"


def probe_url(provider: dict) -> str:
    probe_urls = provider.get("probe_urls", [])
    if probe_urls:
        return probe_urls[0]
    if provider["id"] == "openrouter":
        return "https://openrouter.ai/api/v1/key"
    base_urls = [item.rstrip("/") for item in provider.get("base_urls", [])]
    if not base_urls:
        return ""
    non_anthropic = [item for item in base_urls if "anthropic" not in item]
    versioned = [item for item in non_anthropic if item.endswith("/v1") or item.endswith("/v2") or item.endswith("/v3") or item.endswith("/v4")]
    base_url = (versioned or non_anthropic or base_urls)[0]
    if base_url.endswith("/models"):
        return base_url
    return base_url + "/models"


def unique_sorted(values: list[str]) -> list[str]:
    return sorted({item.strip() for item in values if item and item.strip()})


def source_opener() -> urllib.request.OpenerDirector:
    handlers = []
    try:
        import certifi  # type: ignore[import-not-found]

        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=certifi.where())))
    except ImportError:
        pass
    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = [("User-Agent", USER_AGENT)]
    return opener


def required_env_groups(provider: dict) -> list[list[str]]:
    groups = provider.get("required_env_groups") or [[env_name] for env_name in provider.get("env", [])]
    return [unique_sorted(group) for group in groups if unique_sorted(group)]


def auth_env(provider: dict, group: list[str]) -> str:
    credentials = [env_name for env_name in provider.get("credential_env", []) if env_name in group]
    if credentials:
        return sorted(credentials)[0]
    for suffix in ("_API_KEY", "_ACCESS_TOKEN", "_TOKEN", "_KEY", "_CREDENTIAL"):
        for env_name in group:
            if env_name.endswith(suffix):
                return env_name
    return group[0]


def probe_sources(provider: dict, group: list[str]) -> list[str]:
    sources: list[str] = []
    for env_name in provider.get("base_url_env", []):
        if env_name in group:
            sources.append("env:" + env_name)
    static_probe = probe_url(provider)
    if static_probe:
        sources.append(static_probe)
    if not sources:
        sources.extend("env:" + env_name for env_name in provider.get("base_url_env", []))
    return unique_sorted(sources)


def canonicalize(catalog: dict) -> dict:
    out = {
        "schema_version": catalog.get("schema_version", SCHEMA_VERSION),
        "generated_at": catalog.get("generated_at") or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source_policy": catalog.get("source_policy", ""),
        "providers": [],
    }
    for provider in catalog.get("providers", []):
        normalized = {
            "id": provider["id"].strip(),
            "name": provider["name"].strip(),
            "regions": unique_sorted(provider.get("regions", [])),
            "protocols": unique_sorted(provider.get("protocols", [])),
            "env": unique_sorted(provider.get("env", [])),
            "base_urls": unique_sorted([normalize_url(item) for item in provider.get("base_urls", [])]),
            "source_urls": unique_sorted([normalize_url(item) for item in provider.get("source_urls", [])]),
        }
        credential_env = unique_sorted(provider.get("credential_env", []))
        if credential_env:
            normalized["credential_env"] = credential_env
        groups = required_env_groups(provider)
        if provider.get("required_env_groups") and groups:
            normalized["required_env_groups"] = groups
        base_url_env = unique_sorted(provider.get("base_url_env", []))
        if base_url_env:
            normalized["base_url_env"] = base_url_env
        probe_urls = unique_sorted([normalize_url(item) for item in provider.get("probe_urls", [])])
        if probe_urls:
            normalized["probe_urls"] = probe_urls
        allowed_host_suffixes = unique_sorted(provider.get("allowed_host_suffixes", []))
        if allowed_host_suffixes:
            normalized["allowed_host_suffixes"] = allowed_host_suffixes
        out["providers"].append(normalized)
    out["providers"].sort(key=lambda item: item["id"])
    return out


def validate(catalog: dict) -> list[str]:
    errors: list[str] = []
    if catalog.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    seen_ids: set[str] = set()
    seen_destinations: dict[str, str] = {}
    providers = catalog.get("providers")
    if not isinstance(providers, list) or not providers:
        errors.append("providers must be a non-empty list")
        return errors
    covered_regions: set[str] = set()
    for provider in providers:
        provider_id = provider.get("id", "")
        if not provider_id:
            errors.append("provider id is required")
            continue
        if provider_id in seen_ids:
            errors.append(f"duplicate provider id {provider_id}")
        seen_ids.add(provider_id)
        regions = provider.get("regions", [])
        if not regions:
            errors.append(f"{provider_id}: regions is required")
        for region in regions:
            if region not in VALID_REGIONS:
                errors.append(f"{provider_id}: unsupported region {region}")
            covered_regions.add(region)
        for field in ("name", "protocols", "env", "source_urls"):
            if not provider.get(field):
                errors.append(f"{provider_id}: {field} is required")
        if not provider.get("base_urls") and not provider.get("base_url_env"):
            errors.append(f"{provider_id}: base_urls or base_url_env is required")
        env_names = set(provider.get("env", []))
        for env_name in provider.get("credential_env", []):
            if env_name not in env_names:
                errors.append(f"{provider_id}: credential_env references undeclared env {env_name}")
        for group in provider.get("required_env_groups", []):
            if not group:
                errors.append(f"{provider_id}: required_env_groups contains an empty group")
            for env_name in group:
                if env_name not in env_names:
                    errors.append(f"{provider_id}: required_env_groups references undeclared env {env_name}")
        for env_name in provider.get("base_url_env", []):
            if env_name not in env_names:
                errors.append(f"{provider_id}: base_url_env references undeclared env {env_name}")
        for suffix in provider.get("allowed_host_suffixes", []):
            if not suffix or "/" in suffix or ":" in suffix:
                errors.append(f"{provider_id}: invalid allowed_host_suffixes entry {suffix!r}")
        for base_url in provider.get("base_urls", []):
            try:
                dest = destination(base_url)
            except ValueError as exc:
                errors.append(f"{provider_id}: {exc}")
                continue
            owner = seen_destinations.get(dest)
            if owner and owner != provider_id:
                errors.append(f"{provider_id}: destination {dest} already owned by {owner}")
            seen_destinations[dest] = provider_id
        for probe_url in provider.get("probe_urls", []):
            try:
                destination(probe_url)
            except ValueError as exc:
                errors.append(f"{provider_id}: invalid probe_url: {exc}")
                continue
    for region in sorted(VALID_REGIONS - covered_regions):
        errors.append(f"catalog does not cover required region {region}")
    return errors


def check_sources(catalog: dict, strict: bool) -> list[str]:
    failures: list[str] = []
    opener = source_opener()
    for provider in catalog.get("providers", []):
        provider_id = provider.get("id", "<unknown>")
        for source in provider.get("source_urls", []):
            request = urllib.request.Request(source, method="GET")
            try:
                with opener.open(request, timeout=15) as response:
                    status = getattr(response, "status", 0)
                    if status >= 400:
                        failures.append(f"{provider_id}: {source} returned HTTP {status}")
            except (urllib.error.URLError, TimeoutError) as exc:
                failures.append(f"{provider_id}: {source} unreachable: {exc}")
    if failures and not strict:
        for failure in failures:
            print(f"warning: {failure}", file=sys.stderr)
        return []
    return failures


def collect_source_fingerprints(catalog: dict, strict: bool) -> tuple[dict, list[str]]:
    records: list[dict] = []
    failures: list[str] = []
    opener = source_opener()
    for provider in catalog.get("providers", []):
        provider_id = provider.get("id", "<unknown>")
        for source in provider.get("source_urls", []):
            request = urllib.request.Request(source, method="GET")
            try:
                with opener.open(request, timeout=20) as response:
                    body = response.read()
                    status = getattr(response, "status", 0)
                    record = {
                        "provider_id": provider_id,
                        "source_url": source,
                        "final_url": normalize_url(response.geturl()),
                        "http_status": status,
                        "content_type": response.headers.get("Content-Type", "").split(";")[0].strip(),
                        "content_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
                        "content_length": len(body),
                    }
                    records.append(record)
                    if status >= 400:
                        failures.append(f"{provider_id}: {source} returned HTTP {status}")
            except (urllib.error.URLError, TimeoutError) as exc:
                failures.append(f"{provider_id}: {source} unreachable: {exc}")
                records.append(
                    {
                        "provider_id": provider_id,
                        "source_url": source,
                        "reachable": False,
                    }
                )
    records.sort(key=lambda item: (item.get("provider_id", ""), item.get("source_url", "")))
    payload = {
        "schema_version": FINGERPRINT_SCHEMA_VERSION,
        "source_policy": "Generated from official model provider source_urls. A diff means upstream provider documentation changed and the catalog should be reviewed.",
        "sources": records,
    }
    if failures and not strict:
        for failure in failures:
            print(f"warning: {failure}", file=sys.stderr)
        failures = []
    return payload, failures


def write_catalog(path: Path, catalog: dict) -> None:
    path.write_text(json.dumps(catalog, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def render_helper(catalog: dict) -> str:
    lines = [
        "#!/bin/sh",
        "set -eu",
        "",
        "# Generated by scripts/launch/update_model_provider_catalog.py --write.",
        "",
        "# Egress can be enforced two ways: honor-based (HTTP(S)_PROXY env, the",
        "# local-container substrate) or transparently (iptables REDIRECT into a",
        "# sidecar, the Kubernetes substrate — see docs/launchpad/K8S_SMOKE.md).",
        "# In the transparent mode the workload carries no proxy env by design, so",
        "# HELM_EGRESS_TRANSPARENT marks it; a genuinely dead egress is still caught",
        "# below when curl returns 000.",
        'if [ -z "${HTTPS_PROXY:-}" ] && [ -z "${HTTP_PROXY:-}" ] && [ -z "${HELM_EGRESS_TRANSPARENT:-}" ]; then',
        '  echo "Launchpad egress proxy missing" >&2',
        "  exit 43",
        "fi",
        "",
        'requested_provider="${HELM_MODEL_GATEWAY_PROVIDER:-${HELM_LAUNCHPAD_MODEL_PROVIDER:-}}"',
        "found_key=0",
        "unreachable_provider=\"\"",
        "unreachable_env=\"\"",
        "",
        "candidate() {",
        "  provider=\"$1\"",
        "  auth_env=\"$2\"",
        "  url_source=\"$3\"",
        "  shift 3",
        '  if [ -n "$requested_provider" ] && [ "$requested_provider" != "$provider" ]; then',
        "    return 0",
        "  fi",
        "  for required_env in \"$@\"; do",
        '    eval "required_value=\\${$required_env:-}"',
        '    if [ -z "$required_value" ]; then',
        "      return 0",
        "    fi",
        "  done",
        "  found_key=1",
        '  eval "value=\\${$auth_env:-}"',
        '  if [ -z "$value" ]; then',
        "    return 0",
        "  fi",
        '  case "$url_source" in',
        '    env:*)',
        '      url_env="${url_source#env:}"',
        '      eval "url=\\${$url_env:-}"',
        "      ;;",
        "    *)",
        '      url="$url_source"',
        "      ;;",
        "  esac",
        '  if [ -z "$url" ]; then',
        "    return 0",
        "  fi",
        '  status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 \\',
        '    --output /dev/null --write-out "%{http_code}" \\',
        '    -H "Authorization: Bearer ${value}" \\',
        '    "${url}" || true)"',
        "  # Ready only on a 2xx — the provider is both reachable AND accepted the",
        "  # credential. A 401/403 (bad key), 5xx, or 000 (dead egress) is NOT ready:",
        "  # record the reason and fall through to the next candidate. Gating on 2xx",
        "  # (rather than 'any HTTP status') is what makes the negative smoke with a",
        "  # fake key correctly stay not-ready — see docs/launchpad/K8S_SMOKE.md §138.",
        '  case "$status" in',
        "    2[0-9][0-9])",
        '      echo "Model provider ${provider} reachable and authorized through Launchpad egress proxy using ${auth_env} (HTTP ${status})"',
        "      exit 0",
        "      ;;",
        "    000)",
        "      unreachable_provider=\"$provider\"",
        "      unreachable_env=\"$auth_env\"",
        "      return 0",
        "      ;;",
        "    *)",
        "      unreachable_provider=\"$provider\"",
        "      unreachable_env=\"$auth_env\"",
        '      echo "Model provider ${provider} reachable but rejected credential ${auth_env} (HTTP ${status})" >&2',
        "      return 0",
        "      ;;",
        "  esac",
        "}",
        "",
    ]
    for provider in catalog["providers"]:
        for group in required_env_groups(provider):
            quoted_group = " ".join(f'"{env_name}"' for env_name in group)
            for url in probe_sources(provider, group):
                lines.append(f'candidate "{provider["id"]}" "{auth_env(provider, group)}" "{url}" {quoted_group}')
    lines.extend(
        [
            "",
            'if [ "$found_key" = "0" ]; then',
            '  if [ -n "$requested_provider" ]; then',
            '    echo "No API key found for requested model provider ${requested_provider}" >&2',
            "  else",
            '    echo "No supported BYO model provider API key found" >&2',
            "  fi",
            "  exit 42",
            "fi",
            "",
            'echo "No configured BYO model provider was reachable AND authorized through Launchpad egress proxy; last failing provider ${unreachable_provider} using ${unreachable_env}" >&2',
            "exit 44",
            "",
        ]
    )
    return "\n".join(lines)


def write_helper(path: Path, catalog: dict) -> None:
    path.write_text(render_helper(catalog), encoding="utf-8")
    path.chmod(0o755)


def render_summary(catalog: dict) -> str:
    regions = {region: [] for region in sorted(VALID_REGIONS)}
    dynamic_endpoint_providers: list[str] = []
    source_count = 0
    for provider in catalog["providers"]:
        provider_id = provider["id"]
        source_count += len(provider.get("source_urls", []))
        if provider.get("base_url_env"):
            dynamic_endpoint_providers.append(provider_id)
        for region in provider.get("regions", []):
            regions.setdefault(region, []).append(provider_id)

    lines = [
        "# Launchpad Model Provider Catalog",
        "",
        f"- Providers: {len(catalog['providers'])}",
        f"- Official source URLs: {source_count}",
        f"- Dynamic endpoint providers: {', '.join(sorted(dynamic_endpoint_providers)) or 'none'}",
        "",
        "## Regional Coverage",
    ]
    for region, provider_ids in sorted(regions.items()):
        lines.append(f"- {region}: {len(provider_ids)} providers")
        lines.append(f"  `{', '.join(sorted(provider_ids))}`")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--write", action="store_true", help="rewrite the catalog in canonical order")
    parser.add_argument("--network", action="store_true", help="check source URLs for reachability")
    parser.add_argument("--strict-network", action="store_true", help="treat source URL failures as hard failures")
    parser.add_argument("--summary", action="store_true", help="print a Markdown coverage summary")
    args = parser.parse_args()

    catalog = canonicalize(load_catalog(args.catalog))
    errors = validate(catalog)
    if args.network:
        errors.extend(check_sources(catalog, args.strict_network))
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    if args.write:
        write_catalog(args.catalog, catalog)
        if args.catalog == CATALOG:
            if args.network:
                source_fingerprints, fingerprint_errors = collect_source_fingerprints(catalog, args.strict_network)
                errors.extend(fingerprint_errors)
                if errors:
                    for error in errors:
                        print(f"error: {error}", file=sys.stderr)
                    return 1
                write_json(SOURCE_FINGERPRINTS, source_fingerprints)
            write_helper(HELPER, catalog)
    if args.summary:
        print(render_summary(catalog))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
