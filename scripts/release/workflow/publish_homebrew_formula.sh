#!/usr/bin/env bash
set -e

if [ -z "$HOMEBREW_TAP_TOKEN" ]; then
  echo "::error::HOMEBREW_TAP_TOKEN not configured; cannot publish a complete lockstep release."
  exit 1
fi
git config --global user.name "mindburn-release-bot"
git config --global user.email "release@mindburn.org"
git clone "https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/Mindburn-Labs/homebrew-tap.git" tap
branch="release/helm-ai-kernel-${GITHUB_REF_NAME}"
mkdir -p tap/Formula
cp Formula/helm-ai-kernel.rb tap/Formula/helm-ai-kernel.rb
cd tap
if [ -z "$(git status --porcelain -- Formula/helm-ai-kernel.rb)" ]; then
  echo "Homebrew formula already matches ${GITHUB_REF_NAME}."
  exit 0
fi
git checkout -B "$branch"
git add Formula/helm-ai-kernel.rb
git commit -m "Update helm-ai-kernel formula to ${GITHUB_REF_NAME}"
git push --force-with-lease origin "$branch"

export GH_TOKEN="$HOMEBREW_TAP_TOKEN"
pr="$(gh pr list \
  --repo Mindburn-Labs/homebrew-tap \
  --head "$branch" \
  --base main \
  --state open \
  --json number \
  --jq '.[0].number // ""')"
if [ -z "$pr" ]; then
  pr_url="$(gh pr create \
    --repo Mindburn-Labs/homebrew-tap \
    --base main \
    --head "$branch" \
    --title "Update helm-ai-kernel formula to ${GITHUB_REF_NAME}" \
    --body "Automated Homebrew formula update for helm-ai-kernel ${GITHUB_REF_NAME} from the signed release asset.")"
  pr="${pr_url##*/}"
fi
gh pr merge "$pr" \
  --repo Mindburn-Labs/homebrew-tap \
  --squash \
  --auto \
  --delete-branch
for attempt in $(seq 1 120); do
  state="$(gh pr view "$pr" \
    --repo Mindburn-Labs/homebrew-tap \
    --json state \
    --jq '.state')"
  case "$state" in
    MERGED) exit 0 ;;
    CLOSED)
      echo "::error::Homebrew PR #${pr} closed without merging."
      exit 1
      ;;
    OPEN) echo "Waiting for Homebrew PR #${pr} to reach MERGED (${attempt}/120)." ;;
    *)
      echo "::error::Homebrew PR #${pr} has unexpected state ${state}."
      exit 1
      ;;
  esac
  sleep 5
done
echo "::error::Timed out waiting for Homebrew PR #${pr} to reach MERGED."
exit 1
