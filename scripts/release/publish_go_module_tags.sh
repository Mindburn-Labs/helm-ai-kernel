#!/usr/bin/env bash
# Publish subdirectory-module tags at an existing, immutable root release.
set -euo pipefail

release_ref="${1:?usage: publish_go_module_tags.sh vMAJOR.MINOR.PATCH}"
if [[ ! "$release_ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid release tag: $release_ref" >&2
  exit 1
fi
target="$(git rev-parse --verify "refs/tags/${release_ref}^{commit}")"
remote_release="$(git ls-remote --tags origin "refs/tags/${release_ref}" "refs/tags/${release_ref}^{}")"
published_target="$(awk 'NR == 1 {sha=$1} /\^\{\}$/ {sha=$1} END {print sha}' <<< "$remote_release")"
if [[ "$published_target" != "$target" ]]; then
  echo "Root release ${release_ref} must already be published at ${target}." >&2
  exit 1
fi
refs=()
missing=()

# Preflight every module before creating or publishing any tag. A failed
# remote lookup must fail closed, rather than be treated as a missing tag.
for module in core sdk/go; do
  tag="${module}/${release_ref}"
  declared="$(git show "${target}:${module}/go.mod" | sed -n 's/^module //p')"
  if [[ "$declared" != "github.com/Mindburn-Labs/helm-ai-kernel/${module}" ]]; then
    echo "Unexpected module path for ${module}: ${declared}" >&2
    exit 1
  fi
  remote="$(git ls-remote --tags origin "refs/tags/${tag}" "refs/tags/${tag}^{}")"
  existing="$(awk 'NR == 1 {sha=$1} /\^\{\}$/ {sha=$1} END {print sha}' <<< "$remote")"
  if [[ -n "$existing" ]]; then
    if [[ "$existing" != "$target" ]]; then
      echo "Refusing to move ${tag}: remote points at ${existing}, expected ${target}." >&2
      exit 1
    fi
    echo "${tag} already published at ${target}."
    continue
  fi
  if git rev-parse --verify --quiet "refs/tags/${tag}" >/dev/null; then
    existing="$(git rev-parse "refs/tags/${tag}^{commit}")"
    if [[ "$existing" != "$target" ]]; then
      echo "Refusing to move local ${tag}: expected ${target}." >&2
      exit 1
    fi
  else
    missing+=("$tag")
  fi
  refs+=("refs/tags/${tag}")
done

for tag in "${missing[@]}"; do
  git -c user.name=mindburn-release-bot -c user.email=release@mindburn.org \
    tag -a "$tag" "$target" -m "Release Go module ${tag}"
done
if [[ ${#refs[@]} -gt 0 ]]; then
  git push --atomic origin "${refs[@]}"
fi
