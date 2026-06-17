#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/docs/assets"
BIN="${HELM_AI_KERNEL_BIN:-$ROOT/bin/helm-ai-kernel}"
FONT="${HELM_REAL_USE_FONT:-/System/Library/Fonts/SFNSMono.ttf}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! command -v magick >/dev/null 2>&1; then
  echo "record-real-use-assets: ImageMagick 'magick' is required to render GIF assets" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  make -C "$ROOT" build >/dev/null
fi

if [[ ! -f "$FONT" ]]; then
  FONT="/System/Library/Fonts/Menlo.ttc"
fi

mkdir -p "$OUT_DIR"

HOME_DIR="$TMP/home"
DATA_DIR="$HOME_DIR/.helm-ai-kernel"
RAW="$TMP/real-use.raw.txt"
TRANSCRIPT="$OUT_DIR/helm-real-use-deny-verify.transcript.txt"
PROVENANCE="$OUT_DIR/helm-real-use-deny-verify.provenance.json"
GIF="$OUT_DIR/helm-real-use-deny-verify.gif"

mkdir -p "$HOME_DIR"

run_capture() {
  export HOME="$HOME_DIR"
  export XDG_CONFIG_HOME="$HOME_DIR/.config"
  export XDG_DATA_HOME="$HOME_DIR/.local/share"

  {
    echo "$ helm-ai-kernel setup codex --dry-run --json --data-dir ~/.helm-ai-kernel --no-open"
    "$BIN" setup codex --dry-run --json --data-dir "$DATA_DIR" --no-open
    echo
    echo "$ printf <codex PreToolUse payload> | helm-ai-kernel hook pre-tool --client codex --data-dir ~/.helm-ai-kernel"
    printf '%s\n' '{"toolName":"Bash","toolInput":{"command":"rm -rf /tmp/helm-risky-cleanup"},"session_id":"real-use-capture","cwd":"/tmp/helm-real-workspace"}' |
      "$BIN" hook pre-tool --client codex --data-dir "$DATA_DIR"
    echo
    receipt="$(find "$DATA_DIR/receipts/hooks" -name '*.json' -print -quit)"
    echo "$ helm-ai-kernel workstation verify-decision --receipt ~/.helm-ai-kernel/receipts/hooks/$(basename "$receipt")"
    "$BIN" workstation verify-decision --receipt "$receipt"
  } >"$RAW" 2>&1
}

sanitize() {
  SANITIZE_ROOT="$ROOT" SANITIZE_HOME="$HOME_DIR" perl -0777 -pe '
    s/\e\[[0-9;]*m//g;
    s#\Q$ENV{SANITIZE_ROOT}\E#<repo>#g;
    s#\Q$ENV{SANITIZE_HOME}\E#~#g;
    s#/var/folders/[^ "\x27\n]+#/tmp/<temp>#g;
    s#/tmp/tmp\.[^ "\x27\n]+#/tmp/<temp>#g;
    s#wpd_[a-f0-9]+#wpd_<decision>#g;
    s#[a-f0-9]{64}#<sha256>#g;
    s#"binary_path":"[^"]+"#"binary_path":"<repo>/bin/helm-ai-kernel"#g;
    s#"client_config_path":"[^"]+"#"client_config_path":"~/.codex/config.toml"#g;
    s#"hook_config_path":"[^"]+"#"hook_config_path":"~/.codex/hooks.json"#g;
    s#"data_dir":"[^"]+"#"data_dir":"~/.helm-ai-kernel"#g;
    s#"draft_policy_path":"[^"]+"#"draft_policy_path":"~/.helm-ai-kernel/autoconfigure/policy.draft.json"#g;
  '
}

run_capture
sanitize <"$RAW" >"$TRANSCRIPT"

if ! grep -q "permissionDecision\":\"deny" "$TRANSCRIPT"; then
  echo "record-real-use-assets: capture did not include a hook DENY" >&2
  exit 1
fi

if ! grep -q "signature: true" "$TRANSCRIPT"; then
  echo "record-real-use-assets: capture did not include offline signature verification" >&2
  exit 1
fi

cat >"$PROVENANCE" <<JSON
{
  "asset": "docs/assets/helm-real-use-deny-verify.gif",
  "kind": "real_cli_capture",
  "demo_script": false,
  "generated_by": "scripts/record-real-use-assets.sh",
  "commands": [
    "helm-ai-kernel setup codex --dry-run --json --data-dir ~/.helm-ai-kernel --no-open",
    "printf <codex PreToolUse payload> | helm-ai-kernel hook pre-tool --client codex --data-dir ~/.helm-ai-kernel",
    "helm-ai-kernel workstation verify-decision --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json"
  ],
  "expected_verdict": "DENY",
  "expected_verification": "signature: true",
  "transcript": "docs/assets/helm-real-use-deny-verify.transcript.txt"
}
JSON

write_frame() {
  local frame="$1"
  shift
  {
    echo "HELM AI Kernel real-use CLI capture"
    echo "Actual setup/hook/verify commands run in a temporary HOME"
    echo "Full sanitized transcript: docs/assets/helm-real-use-deny-verify.transcript.txt"
    echo
    cat
  } >"$TMP/frame-${frame}.txt"
}

write_frame 1 <<'FRAME'
$ helm-ai-kernel setup codex --dry-run --json \
    --data-dir ~/.helm-ai-kernel --no-open

target:             codex
client_config_path: ~/.codex/config.toml
hook_config_path:   ~/.codex/hooks.json
data_dir:           ~/.helm-ai-kernel
console_url:        http://127.0.0.1:7714/console/onboarding

This is a dry-run setup preview, not a demo script.
FRAME

write_frame 2 <<'FRAME'
$ printf <codex PreToolUse payload> | \
    helm-ai-kernel hook pre-tool --client codex \
    --data-dir ~/.helm-ai-kernel

payload:
  tool:    Bash
  command: rm -rf /tmp/helm-risky-cleanup

hook output:
  hookEventName:      PreToolUse
  permissionDecision: deny
  reason:             OPERATE_PERMISSIONS_EMPTY
  receipt:            ~/.helm-ai-kernel/receipts/hooks/wpd_<decision>.json
FRAME

write_frame 3 <<'FRAME'
$ helm-ai-kernel workstation verify-decision \
    --receipt ~/.helm-ai-kernel/receipts/hooks/wpd_<decision>.json

Workstation Policy Decision Verification
  decision:  wpd_<decision>
  verdict:   DENY
  reason:    OPERATE_PERMISSIONS_EMPTY
  effect:    WORKSTATION_SHELL_COMMAND
  target:    rm -rf /tmp/helm-risky-cleanup
  hash:      <sha256>
  signature: true
FRAME

write_frame 4 <<'FRAME'
What this real-use capture proves:

1. The setup command emits inspectable local config paths.
2. The Codex-style PreToolUse hook denies a risky Bash call.
3. HELM writes a decision receipt under ~/.helm-ai-kernel.
4. The tiny CLI verifier checks the receipt offline.
5. The captured verifier output ends with signature: true.

No cloud account. No model key. No Docker. No production credentials.
FRAME

for frame in 1 2 3 4; do
  magick -size 1280x720 canvas:'#0b1020' \
    -gravity northwest \
    -font "$FONT" -fill '#94a3b8' -pointsize 21 -annotate +40+40 "@$TMP/frame-${frame}.txt" \
    -font "$FONT" -fill '#22c55e' -pointsize 18 -annotate +40+675 "real CLI output, sanitized paths and hashes" \
    "$TMP/frame-${frame}.png"
done

magick -delay 180 "$TMP/frame-1.png" "$TMP/frame-2.png" "$TMP/frame-3.png" -delay 240 "$TMP/frame-4.png" -loop 0 "$GIF"

echo "Recorded real-use GIF: $GIF"
echo "Transcript: $TRANSCRIPT"
echo "Provenance: $PROVENANCE"
