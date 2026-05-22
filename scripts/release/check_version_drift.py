#!/usr/bin/env python3
"""Check release version drift across local source and published surfaces."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "release" / "version-surfaces.yaml"
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SEMVER_TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")


@dataclass
class SurfaceResult:
    id: str
    status: str
    expected: Any
    actual: Any
    path: str | None = None
    url: str | None = None
    detail: str | None = None
    blocking: bool = True

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "status": self.status,
            "expected": self.expected,
            "actual": self.actual,
            "blocking": self.blocking,
        }
        if self.path:
            payload["path"] = self.path
        if self.url:
            payload["url"] = self.url
        if self.detail:
            payload["detail"] = self.detail
        return payload


def load_contract(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise SystemExit(f"{path} is not JSON-formatted YAML and PyYAML is unavailable") from exc
        return yaml.safe_load(text)


def fmt(value: str, version: str) -> str:
    return value.replace("{version}", version).replace("{tag}", f"v{version}")


def expected_version(contract: dict[str, Any], explicit: str | None) -> str:
    version = explicit
    if version is None:
        version_file = ROOT / contract.get("source_version_file", "VERSION")
        version = version_file.read_text(encoding="utf-8").strip()
    if version.startswith("v"):
        version = version[1:]
    if not SEMVER_RE.match(version):
        raise SystemExit(f"expected a semver version without prerelease: {version}")
    return version


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def unique(values: list[str]) -> list[str]:
    return sorted(set(values))


def is_blocking(surface: dict[str, Any]) -> bool:
    return bool(surface.get("blocking", not surface.get("advisory", False)))


def result_status(actual: Any, expected: Any) -> str:
    return "pass" if actual == expected else "fail"


def read_json_field(path: Path, field: str) -> Any:
    payload = json.loads(path.read_text(encoding="utf-8"))
    current: Any = payload
    for part in field.split("."):
        current = current[part]
    return current


def check_exact(surface: dict[str, Any], version: str) -> list[SurfaceResult]:
    path = ROOT / surface["path"]
    expected = fmt(surface.get("expected", "{version}"), version)
    actual = path.read_text(encoding="utf-8").strip()
    return [SurfaceResult(surface["id"], result_status(actual, expected), expected, actual, path=rel(path), blocking=is_blocking(surface))]


def check_json_surface(surface: dict[str, Any], version: str) -> list[SurfaceResult]:
    path = ROOT / surface["path"]
    expected = fmt(surface.get("expected", "{version}"), version)
    try:
        actual = read_json_field(path, surface["field"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        return [SurfaceResult(surface["id"], "fail", expected, None, path=rel(path), detail=str(exc), blocking=is_blocking(surface))]
    return [SurfaceResult(surface["id"], result_status(str(actual), expected), expected, actual, path=rel(path), blocking=is_blocking(surface))]


def check_regex_on_path(surface: dict[str, Any], version: str, path: Path, result_id: str) -> SurfaceResult:
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(surface["pattern"], re.MULTILINE)
    matches = list(pattern.finditer(text))
    expected = fmt(surface.get("expected", "{version}"), version)
    if not matches:
        return SurfaceResult(result_id, "fail", expected, None, path=rel(path), detail="pattern did not match", blocking=is_blocking(surface))
    actual = [match.group("version") if "version" in match.groupdict() else match.group(0) for match in matches]
    actual_unique = unique(actual)
    status = "pass" if actual_unique == [expected] else "fail"
    return SurfaceResult(result_id, status, expected, actual_unique, path=rel(path), detail=f"{len(matches)} match(es)", blocking=is_blocking(surface))


def check_regex_surface(surface: dict[str, Any], version: str) -> list[SurfaceResult]:
    return [check_regex_on_path(surface, version, ROOT / surface["path"], surface["id"])]


def check_tree_regex_surface(surface: dict[str, Any], version: str) -> list[SurfaceResult]:
    base = ROOT / surface["path"]
    results: list[SurfaceResult] = []
    for path in sorted(base.glob(surface["glob"])):
        if path.is_file():
            results.append(check_regex_on_path(surface, version, path, f"{surface['id']}:{path.relative_to(base).as_posix()}"))
    if not results:
        results.append(SurfaceResult(surface["id"], "fail", version, None, path=rel(base), detail="glob did not match any files", blocking=is_blocking(surface)))
    return results


def check_local(contract: dict[str, Any], version: str, tag: str | None) -> list[SurfaceResult]:
    results: list[SurfaceResult] = []
    if tag is not None:
        expected_tag = f"{contract.get('tag_prefix', 'v')}{version}"
        if not SEMVER_TAG_RE.match(tag):
            results.append(SurfaceResult("git-tag", "skipped", expected_tag, tag, detail="non-semver tag ignored by lockstep policy", blocking=False))
        else:
            results.append(SurfaceResult("git-tag", "pass" if tag == expected_tag else "fail", expected_tag, tag, detail="semver tag must match checked-in VERSION", blocking=True))

    for surface in contract.get("local_surfaces", []):
        kind = surface["kind"]
        if kind == "exact":
            results.extend(check_exact(surface, version))
        elif kind == "json":
            results.extend(check_json_surface(surface, version))
        elif kind == "regex":
            results.extend(check_regex_surface(surface, version))
        elif kind == "tree_regex":
            results.extend(check_tree_regex_surface(surface, version))
        else:
            results.append(SurfaceResult(surface["id"], "fail", version, None, path=surface.get("path"), detail=f"unsupported local surface kind: {kind}", blocking=is_blocking(surface)))
    return results


def http_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {"Accept": "application/json", "User-Agent": "MindburnLabs-VersionDriftGuard/1.0"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra:
        headers.update(extra)
    return headers


def request_json(url: str) -> Any:
    req = urllib.request.Request(url, headers=http_headers())
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def request_text(url: str) -> str:
    req = urllib.request.Request(url, headers=http_headers())
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read().decode("utf-8")


def published_error(surface: dict[str, Any], version: str, exc: Exception) -> SurfaceResult:
    return SurfaceResult(surface["id"], "fail", version, None, url=fmt(surface.get("human_url") or surface.get("url", ""), version), detail=str(exc), blocking=True)


def check_github_release(surface: dict[str, Any], version: str) -> SurfaceResult:
    url = fmt(surface["url"], version)
    payload = request_json(url)
    actual = payload.get("tag_name")
    expected = f"v{version}"
    return SurfaceResult(surface["id"], "pass" if actual == expected else "fail", expected, actual, url=fmt(surface["human_url"], version))


def check_npm(surface: dict[str, Any], version: str) -> SurfaceResult:
    payload = request_json(surface["url"])
    actual = payload.get("dist-tags", {}).get("latest")
    return SurfaceResult(surface["id"], "pass" if actual == version else "fail", version, actual, url=surface["human_url"])


def check_pypi(surface: dict[str, Any], version: str) -> SurfaceResult:
    payload = request_json(surface["url"])
    actual = payload.get("info", {}).get("version")
    return SurfaceResult(surface["id"], "pass" if actual == version else "fail", version, actual, url=surface["human_url"])


def check_crates(surface: dict[str, Any], version: str) -> SurfaceResult:
    payload = request_json(surface["url"])
    actual = payload.get("crate", {}).get("newest_version")
    return SurfaceResult(surface["id"], "pass" if actual == version else "fail", version, actual, url=surface["human_url"])


def check_maven(surface: dict[str, Any], version: str) -> SurfaceResult:
    root = ET.fromstring(request_text(surface["url"]))
    actual = {"latest": root.findtext("./versioning/latest"), "release": root.findtext("./versioning/release")}
    expected = {"latest": version, "release": version}
    return SurfaceResult(surface["id"], "pass" if actual == expected else "fail", expected, actual, url=surface["human_url"])


def check_artifacthub(surface: dict[str, Any], version: str) -> SurfaceResult:
    payload = request_json(surface["url"])
    actual = {"version": payload.get("version"), "app_version": payload.get("app_version")}
    expected = {"version": version, "app_version": fmt(surface.get("app_version", "v{version}"), version)}
    return SurfaceResult(surface["id"], "pass" if actual == expected else "fail", expected, actual, url=surface["human_url"])


def check_homebrew_formula(surface: dict[str, Any], version: str) -> SurfaceResult:
    text = request_text(surface["url"])
    actual = {
        "version": unique(re.findall(r'^\s*version "([0-9]+\.[0-9]+\.[0-9]+)"', text, re.MULTILINE)),
        "release_tags": unique(re.findall(r"/releases/download/(v[0-9]+\.[0-9]+\.[0-9]+)/", text)),
    }
    expected = {"version": [version], "release_tags": [f"v{version}"]}
    return SurfaceResult(surface["id"], "pass" if actual == expected else "fail", expected, actual, url=surface["human_url"])


def ghcr_tags(repository: str) -> list[str]:
    token_url = f"https://ghcr.io/token?scope=repository:{repository}:pull&service=ghcr.io"
    token = request_json(token_url)["token"]
    req = urllib.request.Request(f"https://ghcr.io/v2/{repository}/tags/list", headers=http_headers({"Authorization": f"Bearer {token}"}))
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload.get("tags") or []


def check_ghcr_tags(surface: dict[str, Any], version: str) -> SurfaceResult:
    expected = [fmt(tag, version) for tag in surface["required_tags"]]
    tags = ghcr_tags(surface["repository"])
    missing = sorted(set(expected) - set(tags))
    return SurfaceResult(surface["id"], "pass" if not missing else "fail", expected, sorted(tag for tag in tags if tag in expected), url=surface["human_url"], detail=f"missing tags: {', '.join(missing)}" if missing else None)


def check_http_exists(surface: dict[str, Any], version: str) -> SurfaceResult:
    url = fmt(surface["url"], version)
    req = urllib.request.Request(url, method="HEAD", headers=http_headers())
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            code = response.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    ok_codes = set(surface.get("ok_status", [200, 301, 302, 403]))
    return SurfaceResult(surface["id"], "pass" if code in ok_codes else "fail", sorted(ok_codes), code, url=fmt(surface.get("human_url", url), version))


PUBLISHED_CHECKS = {
    "github_release": check_github_release,
    "npm": check_npm,
    "pypi": check_pypi,
    "crates": check_crates,
    "maven": check_maven,
    "artifacthub": check_artifacthub,
    "homebrew_formula": check_homebrew_formula,
    "ghcr_tags": check_ghcr_tags,
    "http_exists": check_http_exists,
}


def check_published(contract: dict[str, Any], version: str, skip: set[str]) -> list[SurfaceResult]:
    results: list[SurfaceResult] = []
    for surface in contract.get("published_surfaces", []):
        if surface["id"] in skip:
            results.append(SurfaceResult(surface["id"], "skipped", version, None, url=fmt(surface.get("human_url") or surface.get("url", ""), version), detail="skipped by caller", blocking=False))
            continue
        checker = PUBLISHED_CHECKS.get(surface["kind"])
        if checker is None:
            results.append(SurfaceResult(surface["id"], "fail", version, None, url=fmt(surface.get("human_url") or surface.get("url", ""), version), detail=f"unsupported published surface kind: {surface['kind']}"))
            continue
        try:
            results.append(checker(surface, version))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, KeyError, ET.ParseError, json.JSONDecodeError) as exc:
            results.append(published_error(surface, version, exc))
    return results


def should_fail(results: list[SurfaceResult], mode: str) -> bool:
    for result in results:
        if result.status == "fail" and (mode == "published" or result.blocking):
            return True
    return False


def status_payload(mode: str, version: str, results: list[SurfaceResult], source_results: list[SurfaceResult], registry_results: list[SurfaceResult]) -> dict[str, Any]:
    try:
        commit = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        commit = "unknown"
    overall = "fail" if should_fail(results, mode) else "pass"
    return {
        "schema_version": "mindburn.version_status.v1",
        "mode": mode,
        "status": overall,
        "expected_version": version,
        "expected_tag": f"v{version}",
        "source_commit": commit,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source_versions": [result.as_dict() for result in source_results],
        "registry_versions": [result.as_dict() for result in registry_results],
        "surfaces": [result.as_dict() for result in results],
    }


def print_results(results: list[SurfaceResult]) -> None:
    for result in results:
        marker = "OK" if result.status == "pass" else "SKIP" if result.status == "skipped" else "FAIL" if result.blocking else "WARN"
        location = result.path or result.url or ""
        scope = "blocking" if result.blocking else "advisory"
        print(f"{marker} {result.id} [{scope}]: expected={result.expected!r} actual={result.actual!r} {location}")
        if result.detail and result.status != "pass":
            print(f"  {result.detail}")


def write_status(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--expected-version")
    parser.add_argument("--write-status", type=Path)
    parser.add_argument("--report", action="store_true", help="always exit 0 after writing/printing status")
    sub = parser.add_subparsers(dest="mode", required=True)
    local = sub.add_parser("local", help="check source-controlled version surfaces")
    local.add_argument("--tag", help="tag ref to compare, for example v1.2.3")
    published = sub.add_parser("published", help="check public registry surfaces")
    published.add_argument("--skip", action="append", default=[], help="published surface id to skip; can be passed more than once")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    contract = load_contract(args.contract)
    version = expected_version(contract, args.expected_version)

    if args.mode == "local":
        source_results = check_local(contract, version, args.tag)
        registry_results: list[SurfaceResult] = []
        results = source_results
    elif args.mode == "published":
        source_results = check_local(contract, version, None)
        registry_results = check_published(contract, version, set(args.skip))
        results = source_results + registry_results
    else:
        raise AssertionError(args.mode)

    payload = status_payload(args.mode, version, results, source_results, registry_results)
    if args.write_status:
        write_status(args.write_status, payload)
    print_results(results)
    if args.report:
        return 0
    return 1 if payload["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
