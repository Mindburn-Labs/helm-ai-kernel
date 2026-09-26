#!/usr/bin/env bash
# Installs the tools `make check` needs beyond the toolchains that
# Mindburn-Labs/platform-actions ci.yml@v2 sets up on its own (Go, Node,
# Python, Rust, Helm). The caller runs it as `setup-commands` in
# .github/workflows/ci.yml. Every download is pinned by version and sha256.
set -euo pipefail

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
    echo "::error::install_check_tools.sh supports the Linux x86_64 GitHub runner only"
    exit 1
fi
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_PATH:?GITHUB_PATH is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bin_dir="${RUNNER_TEMP}/check-tools/bin"
mkdir -p "$bin_dir"
echo "$bin_dir" >>"$GITHUB_PATH"

# fetch <url> <sha256> <installed name>
fetch() {
    local url="$1" sha256="$2" name="$3" tmp
    tmp="$(mktemp "${RUNNER_TEMP}/download.XXXXXX")"
    curl -fsSL --retry 5 --retry-all-errors -o "$tmp" "$url"
    printf '%s  %s\n' "$sha256" "$tmp" | sha256sum --check --strict -
    case "$url" in
    *.tar.gz) tar -xzf "$tmp" -C "$bin_dir" "$name" ;;
    *) install -m 0755 "$tmp" "${bin_dir}/${name}" ;;
    esac
    rm -f "$tmp"
}

# ripgrep: presentation and unfinished-marker hygiene.
sudo apt-get update -qq
sudo apt-get install --yes --no-install-recommends ripgrep

# PostgreSQL 16 server binaries: the postgres-proofs gate starts a disposable
# cluster from /usr/lib/postgresql/16/bin. The runner image usually has them.
if [ ! -x /usr/lib/postgresql/16/bin/initdb ]; then
    sudo apt-get install --yes --no-install-recommends postgresql-16
fi

# protoc: fixture descriptors and codegen.
bash "${ROOT}/scripts/ci/install_protoc.sh"

# buf: proto lint and breaking-change gate.
fetch https://github.com/bufbuild/buf/releases/download/v1.73.0/buf-Linux-x86_64 \
    8f2986298ad08f0cc1bf999b9797b7c383adf32d7edf0f73d6f1e1a701baeac1 buf

# oasdiff: OpenAPI breaking-change gate (HELM-151). Prebuilt, because its
# module needs a newer Go than the kernel pins.
fetch https://github.com/oasdiff/oasdiff/releases/download/v1.23.0/oasdiff_1.23.0_linux_amd64.tar.gz \
    972b10535c3db4366b9dc3ebc11ca021279af3095267c3cffdca854a3a3c4f89 oasdiff

# kind: Kubernetes install smoke. kind_smoke.sh creates its own cluster.
fetch https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64 \
    aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d kind

# Java 21 (preinstalled Temurin on the runner) for the Java SDK and codegen.
echo "JAVA_HOME=${JAVA_HOME_21_X64:?JAVA_HOME_21_X64 is not set on this runner}" >>"$GITHUB_ENV"
echo "${JAVA_HOME_21_X64}/bin" >>"$GITHUB_PATH"

# Python gate dependencies (hash-locked) and Go protoc plugins for codegen.
python -m pip install --only-binary=:all: --require-hashes -r "${ROOT}/.github/schema-requirements.txt"
python -m pip install --require-hashes -r "${ROOT}/.github/codegen-requirements.txt"
GOBIN="$bin_dir" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
GOBIN="$bin_dir" go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.0
GOBIN="$bin_dir" go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.21.0
