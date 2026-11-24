#!/usr/bin/env bash
set -e

PACKAGE_NAME=$(node -p "require('./package.json').name")
PACKAGE_VERSION=$(node -p "require('./package.json').version")
echo "name=$PACKAGE_NAME" >> "$GITHUB_OUTPUT"
echo "version=$PACKAGE_VERSION" >> "$GITHUB_OUTPUT"
published_version="$(npm view "${PACKAGE_NAME}@${PACKAGE_VERSION}" version 2>/dev/null || true)"
if [ -n "$published_version" ]; then
  if [ "$published_version" != "$PACKAGE_VERSION" ]; then
    echo "::error::Registry metadata mismatch for ${PACKAGE_NAME}@${PACKAGE_VERSION}: got ${published_version}"
    exit 1
  fi
  echo "published=true" >> "$GITHUB_OUTPUT"
else
  echo "published=false" >> "$GITHUB_OUTPUT"
fi
