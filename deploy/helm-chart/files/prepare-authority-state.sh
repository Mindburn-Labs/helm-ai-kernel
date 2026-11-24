set -eu
umask 077
data_dir="$HELM_AUTHORITY_DATA_DIR"
root_key="$data_dir/root.key"
watermark="$data_dir/policy-replay-watermarks.json"
source_key="/var/run/helm-signing-key/root.key"

if [ ! -r "$source_key" ] || [ ! -s "$source_key" ]; then
  echo "authority signing Secret is missing, empty, or unreadable" >&2
  exit 1
fi

if [ ! -d "$data_dir" ] || [ ! -w "$data_dir" ] || [ ! -x "$data_dir" ]; then
  echo "authority data volume is not writable by the restricted runtime identity" >&2
  exit 1
fi

if [ -L "$watermark" ]; then
  echo "refusing symlinked policy replay watermark" >&2
  exit 1
fi
if [ -e "$watermark" ] && [ ! -f "$watermark" ]; then
  echo "policy replay watermark is not a regular file" >&2
  exit 1
fi
if [ -f "$watermark" ] && ! chmod 0600 "$watermark"; then
  echo "could not restore private policy replay watermark mode after fsGroup processing" >&2
  exit 1
fi

if [ -L "$root_key" ]; then
  echo "refusing symlinked durable authority root key" >&2
  exit 1
fi
if [ -e "$root_key" ] && [ ! -f "$root_key" ]; then
  echo "durable authority root key is not a regular file" >&2
  exit 1
fi

# Chart 0.7.x mounted the Secret with subPath at this path. On a
# durable volume kubelet could leave a zero-byte regular file;
# that file is not signing authority. Replace it atomically like
# an absent key, but keep the mismatch guard for every non-empty
# durable key.
if [ -f "$root_key" ] && [ -s "$root_key" ]; then
  if [ ! -r "$root_key" ]; then
    echo "durable authority root key exists but is not readable by the runtime identity" >&2
    exit 1
  fi
  if ! cmp -s "$source_key" "$root_key"; then
    echo "durable authority root key differs from signing Secret; refusing silent rotation" >&2
    exit 1
  fi
  # The invariant is content identity with the Secret, verified
  # above. A matching key written by an earlier release can be
  # owned by a different uid (the pre-init kernel wrote it as the
  # image user), and chmod by a non-owner is EPERM even when the
  # file is readable — that stranded every upgrade from such a
  # volume while a fresh install passed. Tighten the mode when we
  # own the file; never fail an unchanged, verified key over
  # ownership history.
  chmod 0600 "$root_key" 2>/dev/null || true
else
  tmp_key="$data_dir/.root.key.init.$$"
  rm -f "$tmp_key"
  cp "$source_key" "$tmp_key"
  chmod 0600 "$tmp_key"
  mv -f "$tmp_key" "$root_key"
fi
