#!/usr/bin/env bash
set -euo pipefail
# The rule is "never release a commit that is not on main". Requiring
# the tag to EQUAL current origin/main enforced something stricter and
# unachievable: any merge landing while the release runs — or between
# a failed job and its rerun — moved main and made the tagged release
# permanently uncompletable, even though its commit is still on main.
# v0.8.1 hit exactly that: artifacts published from 44bcb7e0, then a
# later merge stranded the run. Ancestry keeps the guarantee (the
# tagged commit is reachable from main, so nothing off-main ships)
# without forbidding the repository to move.
tag_commit="$(git rev-parse "${GITHUB_REF}^{commit}")"
git fetch --quiet origin main
if ! git merge-base --is-ancestor "${tag_commit}" origin/main; then
  main_commit="$(git rev-parse origin/main)"
  echo "::error::Refusing to release ${GITHUB_REF_NAME}: tag commit ${tag_commit} is not reachable from origin/main ${main_commit}."
  exit 1
fi
