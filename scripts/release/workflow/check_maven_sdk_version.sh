#!/usr/bin/env bash
set -euo pipefail
VER=$(cat ../../VERSION)
URL="https://repo1.maven.org/maven2/io/github/mindburnlabs/helm-sdk/${VER}/helm-sdk-${VER}.pom"
code=$(curl -sS -o /dev/null -w "%{http_code}" "$URL")
if [ "$code" = "200" ]; then
  pom="$(curl -fsS "$URL")"
  if ! grep -q "<artifactId>helm-sdk</artifactId>" <<< "$pom" || ! grep -q "<version>${VER}</version>" <<< "$pom"; then
    echo "::error::Maven Central metadata mismatch for helm-sdk ${VER}"
    exit 1
  fi
  echo "helm-sdk ${VER} is already in Maven Central; skipping publish."
  echo "skip=true" >> "$GITHUB_OUTPUT"
else
  echo "helm-sdk ${VER} not in Central yet (HTTP ${code}); proceeding with publish."
  echo "skip=false" >> "$GITHUB_OUTPUT"
fi
