#!/usr/bin/env python3
"""Validate GitHub workflow_dispatch inputs before secret-bearing jobs run."""

from __future__ import annotations

import argparse
import re
import sys


SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
RELEASE_TAG_RE = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
NPM_DIST_TAG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
RUN_ID_RE = re.compile(r"^[1-9]\d{5,19}$")


def validate_version(value: str) -> str:
    value = (value or "").strip()
    if not SEMVER_RE.fullmatch(value):
        raise ValueError("version must be SemVer without a leading v")
    if any(ch in value for ch in "\r\n\t $`'\"\\;|&<>"):
        raise ValueError("version contains characters unsafe for shell or registry contexts")
    return value


def validate_bool(value: str | None, *, field: str) -> bool | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized not in {"true", "false"}:
        raise ValueError(f"{field} must be true or false")
    return normalized == "true"


def validate_release_tag(value: str) -> str:
    value = (value or "").strip()
    if not RELEASE_TAG_RE.fullmatch(value):
        raise ValueError("release_tag must be v<semver>")
    if any(ch in value for ch in "\r\n\t $`'\"\\;|&<>"):
        raise ValueError("release_tag contains characters unsafe for shell contexts")
    return value


def validate_optional_publish_tag(value: str | None, *, version: str) -> str | None:
    if value is None or value.strip() == "":
        return None
    tag = validate_release_tag(value)
    if tag != f"v{version}":
        raise ValueError("release_tag must match v<version>")
    return tag


def validate_npm_dist_tag(value: str | None) -> str:
    value = (value or "latest").strip()
    if not NPM_DIST_TAG_RE.fullmatch(value):
        raise ValueError("dist_tag must start with a letter and contain only letters, numbers, dot, underscore, or dash")
    if SEMVER_RE.fullmatch(value) or RELEASE_TAG_RE.fullmatch(value):
        raise ValueError("dist_tag must not be parseable as SemVer")
    return value


def validate_artifact_run_id(value: str) -> str:
    value = (value or "").strip()
    if not RUN_ID_RE.fullmatch(value):
        raise ValueError("artifact_run_id must be a decimal GitHub Actions run id")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    publish = sub.add_parser("publish")
    publish.add_argument("--version", required=True)
    publish.add_argument("--dry-run", default=None)
    publish.add_argument("--release-tag", default=None)
    publish.add_argument("--dist-tag", default=None)

    clean_install = sub.add_parser("clean-install")
    clean_install.add_argument("--release-tag", required=True)
    clean_install.add_argument("--artifact-run-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "publish":
            version = validate_version(args.version)
            validate_bool(args.dry_run, field="dry_run")
            validate_optional_publish_tag(args.release_tag, version=version)
            validate_npm_dist_tag(args.dist_tag)
        elif args.command == "clean-install":
            validate_release_tag(args.release_tag)
            validate_artifact_run_id(args.artifact_run_id)
        else:
            parser.error(f"unsupported command {args.command!r}")
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
