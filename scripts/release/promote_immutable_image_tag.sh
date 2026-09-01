#!/usr/bin/env sh
set -eu

if [ "$#" -ne 3 ]; then
  echo 'usage: promote_immutable_image_tag.sh <digest-ref> <final-tag> <expected-digest>' >&2
  exit 2
fi

source_ref=$1
final_tag=$2
expected_digest=$3
docker_bin=${DOCKER_BIN:-docker}

if ! printf '%s\n' "$expected_digest" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
  echo "invalid expected digest: $expected_digest" >&2
  exit 2
fi

case "$source_ref" in
  *@"$expected_digest") ;;
  *)
    echo 'source reference must be pinned to the expected digest' >&2
    exit 2
    ;;
esac

inspect_error="$(mktemp)"
trap 'rm -f "$inspect_error"' EXIT HUP INT TERM

if existing_digest="$($docker_bin buildx imagetools inspect "$final_tag" --format '{{.Manifest.Digest}}' 2>"$inspect_error")"; then
  if [ "$existing_digest" != "$expected_digest" ]; then
    echo "immutable tag conflict: $final_tag resolves to $existing_digest, expected $expected_digest" >&2
    exit 1
  fi
  echo 'immutable tag already resolves to expected digest; leaving it unchanged' >&2
else
  if grep -Eiq '(^|[[:space:]:])5[0-9][0-9][[:space:]]+(internal|bad|service|gateway|server|error)' "$inspect_error"; then
    cat "$inspect_error" >&2
    echo "registry server failure while inspecting immutable tag: $final_tag" >&2
    exit 1
  elif grep -Eiq '(unauthorized|authentication required|access denied|forbidden|(^|[[:space:]])(401[[:space:]]+unauthorized|403[[:space:]]+forbidden))' "$inspect_error"; then
    cat "$inspect_error" >&2
    echo "registry authorization failure while inspecting immutable tag: $final_tag" >&2
    exit 1
  elif grep -Eiq '(TLS|timeout|timed out|connection|network|unexpected EOF)' "$inspect_error"; then
    cat "$inspect_error" >&2
    echo "registry transport failure while inspecting immutable tag: $final_tag" >&2
    exit 1
  elif grep -Eiq '(429|rate[-_ ]?limit|too many requests)' "$inspect_error"; then
    cat "$inspect_error" >&2
    echo "registry rate-limit response is ambiguous; unable to prove whether immutable tag exists: $final_tag" >&2
    exit 1
  elif grep -Eiq '(manifest unknown|manifest_unknown|404[[:space:]]+not[[:space:]]+found|:[[:space:]]+not[[:space:]]+found([[:space:]]|$))' "$inspect_error"; then
    echo 'immutable tag is absent; creating it once' >&2
  else
    cat "$inspect_error" >&2
    echo "ambiguous registry failure; unable to prove whether immutable tag exists: $final_tag" >&2
    exit 1
  fi
  $docker_bin buildx imagetools create --tag "$final_tag" "$source_ref"
fi

final_digest="$($docker_bin buildx imagetools inspect "$final_tag" --format '{{.Manifest.Digest}}')"
if [ "$final_digest" != "$expected_digest" ]; then
  echo "immutable tag verification failed: $final_tag resolves to $final_digest, expected $expected_digest" >&2
  exit 1
fi

printf '%s\n' "$final_digest"
