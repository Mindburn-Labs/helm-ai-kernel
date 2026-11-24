#!/usr/bin/env bash
set -e

VERSION="${GITHUB_REF_NAME#v}"
mkdir -p dist/version-status
python3 scripts/release/check_version_drift.py \
  --expected-version "$VERSION" \
  --write-status dist/version-status/version-status.json \
  published \
  --npm-propagation-timeout 900 \
  --pypi-propagation-timeout 900 \
  --only ghcr-image \
  --only ghcr-chart \
  --only npm-sdk \
  --only pypi-sdk \
  --only crates-sdk \
  --only go-proxy-sdk
