"""Version surface results and checks against local source."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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


def unique(values: list[str]) -> list[str]:
    return sorted(set(values))


def is_blocking(surface: dict[str, Any]) -> bool:
    return bool(surface.get("blocking", not surface.get("advisory", False)))


def result_status(actual: Any, expected: Any) -> str:
    return "pass" if actual == expected else "fail"


def semver_parts(value: str, label: str) -> tuple[int, int, int]:
    if not SEMVER_RE.fullmatch(value):
        raise ValueError(f"{label} must be plain semver, got {value!r}")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def read_json_field(path: Path, field: str) -> Any:
    payload = json.loads(path.read_text(encoding="utf-8"))
    current: Any = payload
    for part in field.split("."):
        current = current[part]
    return current


def check_exact(root: Path, surface: dict[str, Any], version: str) -> list[SurfaceResult]:
    path = root / surface["path"]
    expected = fmt(surface.get("expected", "{version}"), version)
    try:
        actual = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        return [SurfaceResult(surface["id"], "fail", expected, None, path=path.relative_to(root).as_posix(), detail=str(exc), blocking=is_blocking(surface))]
    return [SurfaceResult(surface["id"], result_status(actual, expected), expected, actual, path=path.relative_to(root).as_posix(), blocking=is_blocking(surface))]


def check_json_surface(root: Path, surface: dict[str, Any], version: str) -> list[SurfaceResult]:
    path = root / surface["path"]
    expected = fmt(surface.get("expected", "{version}"), version)
    try:
        actual = read_json_field(path, surface["field"])
    except (FileNotFoundError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return [SurfaceResult(surface["id"], "fail", expected, None, path=path.relative_to(root).as_posix(), detail=str(exc), blocking=is_blocking(surface))]
    return [SurfaceResult(surface["id"], result_status(str(actual), expected), expected, actual, path=path.relative_to(root).as_posix(), blocking=is_blocking(surface))]


def check_regex_on_path(root: Path, surface: dict[str, Any], version: str, path: Path, result_id: str) -> SurfaceResult:
    expected = fmt(surface.get("expected", "{version}"), version)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        return SurfaceResult(result_id, "fail", expected, None, path=path.relative_to(root).as_posix(), detail=str(exc), blocking=is_blocking(surface))
    pattern = re.compile(surface["pattern"], re.MULTILINE)
    matches = list(pattern.finditer(text))
    if not matches:
        return SurfaceResult(result_id, "fail", expected, None, path=path.relative_to(root).as_posix(), detail="pattern did not match", blocking=is_blocking(surface))
    actual = [match.group("version") if "version" in match.groupdict() else match.group(0) for match in matches]
    actual_unique = unique(actual)
    status = "pass" if actual_unique == [expected] else "fail"
    return SurfaceResult(result_id, status, expected, actual_unique, path=path.relative_to(root).as_posix(), detail=f"{len(matches)} match(es)", blocking=is_blocking(surface))


def check_regex_surface(root: Path, surface: dict[str, Any], version: str) -> list[SurfaceResult]:
    return [check_regex_on_path(root, surface, version, root / surface["path"], surface["id"])]


def check_tree_regex_surface(root: Path, surface: dict[str, Any], version: str) -> list[SurfaceResult]:
    base = root / surface["path"]
    results: list[SurfaceResult] = []
    for path in sorted(base.glob(surface["glob"])):
        if path.is_file():
            results.append(check_regex_on_path(root, surface, version, path, f"{surface['id']}:{path.relative_to(base).as_posix()}"))
    if not results:
        results.append(SurfaceResult(surface["id"], "fail", version, None, path=base.relative_to(root).as_posix(), detail="glob did not match any files", blocking=is_blocking(surface)))
    return results


def check_local(root: Path, contract: dict[str, Any], version: str, tag: str | None) -> list[SurfaceResult]:
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
            results.extend(check_exact(root, surface, version))
        elif kind == "json":
            results.extend(check_json_surface(root, surface, version))
        elif kind == "regex":
            results.extend(check_regex_surface(root, surface, version))
        elif kind == "tree_regex":
            results.extend(check_tree_regex_surface(root, surface, version))
        else:
            results.append(SurfaceResult(surface["id"], "fail", version, None, path=surface.get("path"), detail=f"unsupported local surface kind: {kind}", blocking=is_blocking(surface)))
    return results
