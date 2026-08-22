---
title: Savings EvidencePack Offline Verification Walkthrough
last_reviewed: 2026-08-17
---

<!-- quantum_posture: this walkthrough re-derives SHA-256 hashes and describes
verification of classical Ed25519 signatures; it adds no cryptographic surface
of its own. -->

# Savings EvidencePack Offline Verification Walkthrough

This is the skeptic's copy-paste path over a **savings EvidencePack** — the
HELM-614 methodology's paired-replay capture (baseline model vs substituted
model over an identical holdout task set) rendered as one content-addressed
pack. Every command below runs **offline**: no provider console, no network,
no live ledger, no receipts directory — only the pack bytes.

The reference pack this walkthrough is written against was captured on
2026-08-18 through the Inference.net OpenAI-compatible gateway and lives in
this repository:

```bash
PACK=reference_packs/spend-savings/savingspack-h618-infnet-20260818
```

Its manifest hash is
`sha256:261cc3cf051a9a4f66696d0ef880526bdd2f74c9fcb44ac4edf2972d13c8f457`,
signed by key `spend-proxy-d11333ad0bbd` (pin this pair out-of-band; see the
provenance note below).

**This reference pack records a NEGATIVE result.** The frozen substitute
(`gpt-4.1-nano`) passed 12 of 16 holdout tasks against the baseline
(`gpt-4.1`) 16 of 16, so the strict parity bar failed and **no savings claim
is made** — even though the substitute's cost per successful task was ~14x
lower. That is the meter working: it can say "no". A pack that fails the
parity bar still verifies; `savings_claim_valid` is simply `false`.

## One command, all checks

`spend-proxy savings-verify` re-runs the full check set from pack bytes alone
and prints each named check:

```bash
helm-ai-kernel spend-proxy savings-verify --pack "$PACK"
```

Expected output ends with `ok=true` and lists every check below. The rest of
this page performs the same checks **without the HELM binary**, so the
verification does not depend on trusting our code. You need `python3`,
`shasum` (or `sha256sum`), and `jq`.

## (a) Re-hash every receipt

Every receipt file's SHA-256 must match its `content_hash` entry in
`manifest.json`, and every receipt's *internal* `content_hash` must equal the
canonical hash of its own fields (the HELM binary checks the second half; the
first half alone already proves the pack bytes are the sealed bytes):

```bash
jq -r '.entries[] | select(.path | startswith("receipts/")) | "\(.content_hash)  \(.path)"' "$PACK/manifest.json" \
| while read -r want path; do
    got="sha256:$(shasum -a 256 "$PACK/$path" | cut -d' ' -f1)"
    [ "$got" = "$want" ] || { echo "MISMATCH: $path"; exit 1; }
  done && echo "all receipt hashes match the manifest"
```

## (b) Re-derive the pack manifest hash

The manifest hash is SHA-256 over the RFC 8785 (JCS) canonicalization of the
manifest without `manifest_hash` and `entries_merkle_root`, entries sorted by
path. For this manifest (ASCII strings and integers only) Python's compact
sorted-keys serialization is byte-identical to JCS:

```bash
python3 - "$PACK" <<'EOF'
import hashlib, json, sys
m = json.load(open(sys.argv[1] + "/manifest.json"))
hashable = {
    "version": m["version"], "pack_id": m["pack_id"], "created_at": m["created_at"],
    "actor_did": m["actor_did"], "intent_id": m["intent_id"], "policy_hash": m["policy_hash"],
    "entries": sorted(m["entries"], key=lambda e: e["path"]),
}
data = json.dumps(hashable, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
got = "sha256:" + hashlib.sha256(data).hexdigest()
assert got == m["manifest_hash"], f"MISMATCH: {got} != {m['manifest_hash']}"
print("manifest hash re-derived:", got)
EOF
```

Also confirm every non-receipt entry's bytes (checked for receipts in (a)):

```bash
jq -r '.entries[] | "\(.content_hash)  \(.path)"' "$PACK/manifest.json" \
| while read -r want path; do
    got="sha256:$(shasum -a 256 "$PACK/$path" | cut -d' ' -f1)"
    [ "$got" = "$want" ] || { echo "MISMATCH: $path"; exit 1; }
  done && echo "every manifest entry matches its bytes"
```

## (c) Recompute CPST from receipts alone

Cost per successful task, per route, on two bases: **settled** (the governed
ledger's integer-cent debits — the SPEND3 engine ceils each call to a whole
cent) and **token-priced** (the settled usage receipts' token counts at the
pack-embedded price book, which every receipt binds via
`provider_price_snapshot_hash`). The savings claim compares the token-priced
basis; both must match `views/savings_view.json` exactly:

```bash
python3 - "$PACK" <<'EOF'
import json, sys, glob
from datetime import datetime


def ts(v):  # robust RFC3339 parse (any fraction width, py3.9+)
    v = v.replace("Z", "+00:00")
    if "." in v:
        head, tail = v.split(".", 1)
        frac, off = tail[:-6], tail[-6:]
        v = head + "." + (frac + "000000")[:6] + off
    return datetime.fromisoformat(v)
pack = sys.argv[1]
view = json.load(open(pack + "/views/savings_view.json"))
man = json.load(open(pack + "/artifacts/task_split_manifest.json"))
res = json.load(open(pack + "/artifacts/task_results.json"))
book = json.load(open(pack + "/artifacts/price_book_config.json"))
prices = {(p["provider_id"], p["model_id"]): p for p in book["prices"]}
frozen = ts(man["selection_freeze"]["frozen_at"])
routes = {view["baseline"]["envelope_id"]: "baseline", view["substitute"]["envelope_id"]: "substitute"}
agg = {r: {"settled_cents": 0, "token_micro": 0, "calls": 0} for r in ("baseline", "substitute")}
for path in glob.glob(pack + "/receipts/*/usage.json"):
    u = json.load(open(path))
    q = json.load(open(path.replace("usage.json", "route_quote.json")))
    if u["envelope_id"] not in routes or ts(q["created_at"]) <= frozen:
        continue  # parity-phase or foreign spend never enters CPST
    r = routes[u["envelope_id"]]
    p = prices[(u["provider_id"], u["model_id"])]
    agg[r]["settled_cents"] += u["balance_debit_cents"]
    agg[r]["token_micro"] += (u.get("input_tokens", 0) * p["input_token_micro_cents"]
                              + u.get("output_tokens", 0) * p["output_token_micro_cents"]
                              + p.get("request_cents", 0) * 1_000_000)
    agg[r]["calls"] += 1
for r in ("baseline", "substitute"):
    v, a = view[r], agg[r]
    passed = v["tasks_passed"]
    assert a["settled_cents"] == v["spend_cents"], (r, "settled spend")
    assert a["token_micro"] == v["token_priced_micro_cents"], (r, "token-priced spend")
    assert a["calls"] == v["settled_calls"], (r, "settled calls")
    assert a["settled_cents"] * 1_000_000 // passed == v["cpst_settled_micro_cents"], (r, "settled CPST")
    assert a["token_micro"] // passed == v["cpst_token_priced_micro_cents"], (r, "token-priced CPST")
b, s = view["baseline"]["cpst_token_priced_micro_cents"], view["substitute"]["cpst_token_priced_micro_cents"]
assert b - s == view["savings_per_task_micro_cents"]
assert (b - s) * 10_000 // b == view["savings_percent_bps"]
print("CPST recomputed from receipts: baseline", b, "substitute", s, "micro-cents/task;",
      "savings", view["savings_per_task_micro_cents"], f"({view['savings_percent_bps']} bps)")
EOF
```

## (d) Recompute pass rates and the parity bar

Strict bar: the substitute must pass **at least as many** holdout tasks as the
baseline over the identical task set:

```bash
python3 - "$PACK" <<'EOF'
import json, sys
pack = sys.argv[1]
view = json.load(open(pack + "/views/savings_view.json"))
res = json.load(open(pack + "/artifacts/task_results.json"))
counts = {}
for r in res["results"]:
    if r["phase"] != "holdout":
        continue
    c = counts.setdefault(r["envelope_id"], [0, 0])
    c[0] += 1
    c[1] += 1 if r["passed"] else 0
base = counts[view["baseline"]["envelope_id"]]
sub = counts[view["substitute"]["envelope_id"]]
assert base == [view["baseline"]["tasks_total"], view["baseline"]["tasks_passed"]]
assert sub == [view["substitute"]["tasks_total"], view["substitute"]["tasks_passed"]]
assert (sub[1] >= base[1]) == view["parity_bar_met"]
print(f"pass rates: baseline {base[1]}/{base[0]}, substitute {sub[1]}/{sub[0]};",
      "parity bar", "MET" if view["parity_bar_met"] else "NOT MET (negative result recorded)")
EOF
```

## (e) Paired task-ID check

Both routes must cover exactly the manifest's holdout set — same task ids, one
result each — and every result's spend intent must have receipts in the pack:

```bash
python3 - "$PACK" <<'EOF'
import json, sys, os
pack = sys.argv[1]
view = json.load(open(pack + "/views/savings_view.json"))
man = json.load(open(pack + "/artifacts/task_split_manifest.json"))
res = json.load(open(pack + "/artifacts/task_results.json"))
holdout = {t["task_id"] for t in man["tasks"] if t["subset"] == "holdout"}
seen = {view["baseline"]["envelope_id"]: set(), view["substitute"]["envelope_id"]: set()}
for r in res["results"]:
    assert os.path.isfile(f"{pack}/receipts/{r['spend_intent_id']}/route_quote.json"), r["spend_intent_id"]
    if r["phase"] == "holdout":
        assert r["task_id"] not in seen[r["envelope_id"]], ("duplicate", r["task_id"])
        seen[r["envelope_id"]].add(r["task_id"])
for env, ids in seen.items():
    assert ids == holdout, (env, "does not cover the holdout set exactly")
print(f"paired: both routes cover the identical {len(holdout)}-task holdout set; every result has receipts")
EOF
```

## (f) Selection freeze precedes holdout

The frozen substitute choice (timestamp + parity-artifact hash inside the
task-split manifest) must strictly precede every holdout call and strictly
follow every parity call, and the frozen choice must be the model the
substitute route actually dispatched:

```bash
python3 - "$PACK" <<'EOF'
import json, sys
from datetime import datetime


def ts(v):  # robust RFC3339 parse (any fraction width, py3.9+)
    v = v.replace("Z", "+00:00")
    if "." in v:
        head, tail = v.split(".", 1)
        frac, off = tail[:-6], tail[-6:]
        v = head + "." + (frac + "000000")[:6] + off
    return datetime.fromisoformat(v)
pack = sys.argv[1]
man = json.load(open(pack + "/artifacts/task_split_manifest.json"))
res = json.load(open(pack + "/artifacts/task_results.json"))
view = json.load(open(pack + "/views/savings_view.json"))
frozen = ts(man["selection_freeze"]["frozen_at"])
for r in res["results"]:
    q = json.load(open(f"{pack}/receipts/{r['spend_intent_id']}/route_quote.json"))
    if r["phase"] == "parity":
        assert ts(q["created_at"]) < frozen, ("parity call after freeze", r["task_id"])
    else:
        assert frozen < ts(q["created_at"]), ("holdout call not after freeze", r["task_id"])
        if r["envelope_id"] == view["substitute"]["envelope_id"]:
            assert q["model_substituted"] is True
            assert q["requested_model_id"] == man["baseline_model_id"]
            assert q["selected_model_id"] == man["selection_freeze"]["chosen_substitute_model_id"]
        else:
            assert q["model_substituted"] is False
            assert q["selected_model_id"] == man["baseline_model_id"]
print("freeze at", frozen, "strictly separates parity from holdout; substitution is truthful")
EOF
```

Confirm the freeze block binds the parity artifact it claims to be based on
(and that the view binds the manifest):

```bash
[ "sha256:$(shasum -a 256 "$PACK/artifacts/parity_prerun.json" | cut -d' ' -f1)" = \
  "$(jq -r '.selection_freeze.parity_results_sha256' "$PACK/artifacts/task_split_manifest.json")" ] \
  && echo "parity artifact hash matches the frozen selection"
[ "sha256:$(shasum -a 256 "$PACK/artifacts/task_split_manifest.json" | cut -d' ' -f1)" = \
  "$(jq -r '.selection_freeze.task_split_manifest_sha256' "$PACK/views/savings_view.json")" ] \
  && echo "task-split manifest hash matches the view"
```

The price book every receipt was quoted on is the embedded one:

```bash
BOOK="sha256:$(shasum -a 256 "$PACK/artifacts/price_book_config.json" | cut -d' ' -f1)"
jq -r --arg want "$BOOK" 'select(.provider_price_snapshot_hash != $want) | "MISMATCH: \(.id)"' \
  "$PACK"/receipts/*/route_quote.json && echo "every quote binds the embedded price book ($BOOK)"
```

## (g) No prompt bodies in views

Business views must never carry prompt or response bodies (the receipts store
token counts and hashes only; task prompts live in the public task set,
referenced by `task_set_sha256`):

```bash
! grep -riE '"(prompt|prompt_body|prompt_text|system_prompt|request_body|response_body|completion_body|messages)"' \
    "$PACK"/views/savings_view.json "$PACK"/views/*receipt_view*.json 2>/dev/null \
  && echo "no prompt-body markers in business views"
```

## Receipt, manifest, and verdict signatures

The sealed `content_hash` on each receipt deliberately omits post-dispatch
fields (token counts, quote timestamps, substitution flags). The pack
therefore anchors them with **detached Ed25519 signatures**, and
`savings-verify` REQUIRES all of the following (their absence fails
verification):

- `receipts/<intent>/receipt_signatures.json` — for every route-quote, usage,
  and settlement receipt: an Ed25519 signature over the RFC 8785 (JCS)
  canonicalization of the receipt JSON, made by the spend-proxy issuer at
  persist time. Rewriting ANY receipt field — including token counts and
  timestamps — breaks it.
- `manifest.sig.json` — the issuer's signature over the raw ASCII bytes of the
  manifest hash. The manifest alone is self-referential (a forger can re-pin
  entry hashes and recompute it); this signature is what makes the pack
  non-regenerable without the capture key.
- `budget_verdict.json` — carries its own embedded seal, checked against the
  same registry.

Quick structural checks without an Ed25519 tool:

```bash
jq -r '.manifest_hash == $mh' --arg mh "$(jq -r .manifest_hash "$PACK/manifest.json")" "$PACK/manifest.sig.json"   && echo "manifest signature covers the pack manifest hash"
KEYID=$(jq -r .key_id "$PACK/manifest.sig.json")
jq -e --arg k "$KEYID" '.keys[$k]' "$PACK/artifacts/trusted_keys.json" >/dev/null   && echo "manifest signing key $KEYID is in the embedded registry"
ls "$PACK"/receipts/*/receipt_signatures.json | wc -l
```

To verify the signatures independently of the HELM binary, use any Ed25519
implementation: the manifest signature is over the `manifest_hash` string
bytes; each receipt signature is over the JCS canonicalization of the receipt
JSON (for these ASCII-only receipts, Python's
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
is byte-identical to JCS). Public keys are hex-encoded in
`artifacts/trusted_keys.json` under `keys.<key_id>.public_key`.

**Provenance note:** the registry travels inside the pack, so signature checks
prove the pack is internally consistent under its declared keys. To prove WHO
produced it, pin the expected `key_id` and public key out-of-band — the
capture record (Linear HELM-618) publishes both for the reference pack — and
compare against `artifacts/trusted_keys.json` before trusting the claim.

## What the claim means

The savings number is bound to the capture window and the embedded price book:
"savings at capture-window prices". A new price regime requires a new capture
and a new pack. When the parity bar is NOT met, the pack still verifies — it
records the negative result, and no savings claim is made.
