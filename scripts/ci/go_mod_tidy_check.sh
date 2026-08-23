#!/usr/bin/env bash
# Fail when any module's go.mod/go.sum is not what `go mod tidy` would produce.
#
# Drift here is invisible until someone runs `go mod tidy` on unrelated work and
# inherits a diff they did not create (#813). `go mod tidy -diff` prints the
# changes and exits non-zero without touching the tree, so this needs no temp
# copies and cannot leave a half-tidied module behind.
#
# -diff landed in Go 1.23, and GOTOOLCHAIN=auto honours each module's own `go`
# directive, so modules pinned below 1.23 run a toolchain that does not have the
# flag. Those are skipped and named below rather than silently passed. Raising
# their `go` directive to the repo's 1.25.13 removes the exception.
set -euo pipefail

MIN_DIFF_GO=1.23

mapfile -t modules < <(git ls-files '**/go.mod' 'go.mod' | xargs -n1 dirname | sort -u)

untidy=()
skipped=()
checked=0

for module in "${modules[@]}"; do
  go_directive="$(awk '/^go [0-9]/ {print $2; exit}' "${module}/go.mod")"
  if [[ -z "${go_directive}" ]] || [[ "$(printf '%s\n%s\n' "${MIN_DIFF_GO}" "${go_directive}" | sort -V | head -1)" != "${MIN_DIFF_GO}" ]]; then
    skipped+=("${module} (go ${go_directive:-unset} < ${MIN_DIFF_GO})")
    continue
  fi
  if ! (cd "${module}" && GOWORK=off go mod tidy -diff); then
    untidy+=("${module}")
  fi
  checked=$((checked + 1))
done

if [[ ${#skipped[@]} -gt 0 ]]; then
  echo "skipped ${#skipped[@]} module(s) without \`go mod tidy -diff\` support:"
  for module in "${skipped[@]}"; do
    echo "  ${module}"
  done
fi

if [[ ${#untidy[@]} -gt 0 ]]; then
  echo ""
  echo "go.mod is not tidy in ${#untidy[@]} module(s). Fix with:"
  for module in "${untidy[@]}"; do
    echo "  (cd ${module} && GOWORK=off go mod tidy)"
  done
  exit 1
fi

echo "go mod tidy check passed: ${checked} module(s) tidy, ${#skipped[@]} skipped."
