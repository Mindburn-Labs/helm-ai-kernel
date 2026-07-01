#!/bin/bash
set -e

# HELM Distribution Script
# Legacy/manual helper only. The maintained lockstep release path is the
# tag-triggered `.github/workflows/release.yml` workflow. Do not use this script
# as release proof or as a substitute for `make quality-release`,
# `make release-assets`, GitHub Release publication, Homebrew fanout, downstream
# fanout, and `make version-drift-published`.
# Usage: ./scripts/release/distribute.sh [version]
# Example: ./scripts/release/distribute.sh 0.1.0

# Load secrets if .env.release exists
if [ -f .env.release ]; then
    echo "🔑 Loading secrets from .env.release..."
    export $(grep -v '^#' .env.release | xargs)
fi

VERSION=$1
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

echo "⚠️  Legacy/manual helper: tag-triggered release.yml is the maintained lockstep release path."
echo "Distributing HELM $VERSION across all ecosystems..."

# 1. Go (via Git Tags)
echo "🐹 Tagging Go SDK..."
GO_TAG="sdk/go/v$VERSION"
GO_TAG_TARGET="$(git rev-parse HEAD^{commit})"
if git rev-parse -q --verify "refs/tags/$GO_TAG" >/dev/null; then
    EXISTING_GO_TAG_TARGET="$(git rev-parse "$GO_TAG^{commit}")"
    if [ "$EXISTING_GO_TAG_TARGET" != "$GO_TAG_TARGET" ]; then
        echo "❌ Go SDK tag $GO_TAG points at $EXISTING_GO_TAG_TARGET, expected $GO_TAG_TARGET."
        echo "   Refusing to move an existing release tag."
        exit 1
    fi
else
    git tag -a "$GO_TAG" -m "Release Go SDK v$VERSION"
fi

REMOTE_GO_TAG_TARGET="$(git ls-remote --tags origin "refs/tags/$GO_TAG^{}" | awk '{print $1}')"
if [ -z "$REMOTE_GO_TAG_TARGET" ]; then
    REMOTE_GO_TAG_TARGET="$(git ls-remote --tags origin "refs/tags/$GO_TAG" | awk '{print $1}')"
fi
if [ -n "$REMOTE_GO_TAG_TARGET" ]; then
    if [ "$REMOTE_GO_TAG_TARGET" != "$GO_TAG_TARGET" ]; then
        echo "❌ Remote Go SDK tag $GO_TAG points at $REMOTE_GO_TAG_TARGET, expected $GO_TAG_TARGET."
        echo "   Refusing to overwrite an existing release tag."
        exit 1
    fi
    echo "ℹ️  Go SDK tag $GO_TAG already exists on origin."
else
    git push origin "refs/tags/$GO_TAG"
fi
echo "✅ Go SDK tagged (v$VERSION)."

# 2. Rust (Crates.io)
echo "🦀 Publishing Rust SDK..."
if [ -z "$CARGO_REGISTRY_TOKEN" ]; then
    echo "⚠️  CARGO_REGISTRY_TOKEN not set. Skipping Rust publish."
else
    cd sdk/rust
    # Update version in Cargo.toml
    sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml && rm Cargo.toml.bak
    # Crates.io requires --allow-dirty if we just modified Cargo.toml
    cargo publish --token "$CARGO_REGISTRY_TOKEN" --allow-dirty
    cd ../..
    echo "✅ Rust SDK published."
fi

# 3. NPM (TypeScript)
echo "📦 Publishing NPM package..."
if [ -z "$NPM_TOKEN" ]; then
    echo "⚠️  NPM_TOKEN not set. Skipping NPM publish."
else
    cd sdk/ts
    npm version "$VERSION" --no-git-tag-version --allow-same-version
    echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc
    npm publish --access public
    rm .npmrc
    cd ../..
    echo "✅ NPM package published."
fi

# 4. PyPI (Python)
echo "🐍 Publishing PyPI package..."
if [ -z "$PYPI_TOKEN" ]; then
    echo "⚠️  PYPI_TOKEN not set. Skipping PyPI publish."
else
    cd sdk/python
    # Update version in pyproject.toml
    sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" pyproject.toml && rm pyproject.toml.bak
    python3 -m pip install -q --require-hashes -r ../../.github/python-build-requirements.txt
    python3 -m build
    twine upload dist/* -u __token__ -p "$PYPI_TOKEN" --skip-existing
    cd ../..
    echo "✅ PyPI package published."
fi

# 5. Maven (Java)
echo "☕ Publishing Java SDK..."
if [ -z "$OSSRH_USERNAME" ]; then
    echo "⚠️  OSSRH_USERNAME not set. Skipping Maven publish."
else
    cd sdk/java
    mvn versions:set -DnewVersion="$VERSION" -DgenerateBackupPoms=false
    if mvn deploy -P release -DskipTests \
        --settings ../../scripts/release/maven-settings.xml \
        -DaltDeploymentRepository=central::https://central.sonatype.com/api/v1/publisher/deployments/upload \
        ${MAVEN_GPG_KEY_FINGERPRINT:+-Dgpg.keyname="$MAVEN_GPG_KEY_FINGERPRINT"} \
        -Dgpg.passphrase="$MAVEN_GPG_PASSPHRASE"; then
        echo "✅ Maven package published."
    else
        echo "⚠️  Maven publication failed."
        echo "   TIP: Status 402 usually means Sonatype Central needs account verification."
    fi
    cd ../..
fi

# 6. Docker
echo "🐳 Publishing Docker image..."
if [ -z "$DOCKER_REPO" ]; then
    echo "⚠️  DOCKER_REPO not set. Skipping Docker publish."
else
    if [ -n "$DOCKER_PASSWORD" ] && [ -n "$DOCKER_USERNAME" ]; then
        echo "🔑 Logging into Docker..."
        echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
    fi
    docker tag helm-ai-kernel:latest "$DOCKER_REPO/helm-ai-kernel:v$VERSION"
    docker tag helm-ai-kernel:latest "$DOCKER_REPO/helm-ai-kernel:latest"
    docker push "$DOCKER_REPO/helm-ai-kernel:v$VERSION"
    docker push "$DOCKER_REPO/helm-ai-kernel:latest"
    echo "✅ Docker image published."
fi

echo "🎉 Full Distribution complete for version $VERSION!"
