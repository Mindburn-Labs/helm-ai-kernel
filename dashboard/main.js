// main.js — wire the UI to the parser/verifier modules.
//
// Flow:
//   1. User drops a .tar file or picks one via the file input.
//   2. We read the file as ArrayBuffer (never leaves the browser).
//   3. parseTar(buf) -> list of entries.
//   4. loadManifest(entries) -> manifest.json contents.
//   5. verifyBlobs(entries, manifest) -> per-blob SHA-256 check.
//   6. loadDecisions / loadProofGraph -> optional sections.
//   7. Render into the panels.

import { parseTar } from "./tar-reader.js";
import {
  loadManifest,
  verifyBlobs,
  loadDecisions,
  loadProofGraph,
} from "./evidencepack.js";
import { renderProofGraph } from "./proofgraph.js";

const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("file-input");
const statusEl = document.getElementById("status");
const manifestView = document.getElementById("manifest-view");
const manifestDl = document.getElementById("manifest-dl");
const verificationView = document.getElementById("verification-view");
const verificationList = document.getElementById("verification-list");
const decisionsView = document.getElementById("decisions-view");
const decisionsTbody = document.getElementById("decisions-tbody");
const proofGraphView = document.getElementById("proofgraph-view");
const proofGraphTree = document.getElementById("proofgraph-tree");

// --- drop zone + file picker wiring ---

["dragenter", "dragover"].forEach((evt) => {
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
  });
});

["dragleave", "drop"].forEach((evt) => {
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
  });
});

dropZone.addEventListener("drop", (e) => {
  const file = e.dataTransfer?.files?.[0];
  if (file) loadFile(file);
});

fileInput.addEventListener("change", (e) => {
  const file = e.target.files?.[0];
  if (file) loadFile(file);
});

// --- core pipeline ---

async function loadFile(file) {
  setStatus("working", `Parsing ${file.name} (${formatBytes(file.size)})…`);
  try {
    const buf = await file.arrayBuffer();
    const entries = parseTar(buf);
    if (entries.length === 0) {
      throw new Error("No readable entries in the archive — is this a valid TAR?");
    }

    const manifest = loadManifest(entries);
    if (!manifest) {
      throw new Error(
        "manifest.json not found inside the pack — required for verification.",
      );
    }

    renderManifest(manifest);

    setStatus("working", "Verifying blob hashes…");
    const verification = await verifyBlobs(entries, manifest);
    renderVerification(verification);

    const decisions = loadDecisions(entries);
    renderDecisions(decisions);

    const proofGraph = loadProofGraph(entries);
    renderProofGraph(proofGraphTree, proofGraph);
    if (proofGraph.length > 0) proofGraphView.classList.remove("hidden");
    else proofGraphView.classList.add("hidden");

    const total = verification.length;
    const passed = verification.filter((v) => v.ok).length;
    if (total === 0) {
      setStatus("ok", `Loaded ${entries.length} entries. (manifest has no file entries to verify — inspect panels below.)`);
    } else if (passed === total) {
      setStatus(
        "ok",
        `Verified ${passed}/${total} blobs · ${entries.length} entries · ${decisions.length} decisions · ${proofGraph.length} ProofGraph nodes. Run \`helm verify\` for signature check.`,
      );
    } else {
      setStatus(
        "err",
        `Verification FAILED: ${total - passed}/${total} blob(s) mismatch. See verification panel for details.`,
      );
    }
  } catch (err) {
    setStatus("err", `Error: ${err.message || err}`);
    console.error(err);
  }
}

// --- rendering helpers ---

function renderManifest(manifest) {
  manifestDl.innerHTML = "";
  const interesting = [
    "version",
    "pack_version",
    "format_version",
    "session_id",
    "created_at",
    "generated_at",
    "actor",
    "principal",
    "helm_version",
    "signature",
  ];
  let shown = 0;
  for (const k of interesting) {
    if (manifest[k] !== undefined) {
      appendDl(manifestDl, k, manifest[k]);
      shown++;
    }
  }
  // If none of the interesting keys matched, show the top-level keys.
  if (shown === 0) {
    for (const [k, v] of Object.entries(manifest)) {
      if (typeof v === "object") continue;
      appendDl(manifestDl, k, v);
      if (++shown >= 10) break;
    }
  }
  manifestView.classList.remove("hidden");
}

function appendDl(parent, key, value) {
  const dt = document.createElement("dt");
  dt.textContent = key;
  const dd = document.createElement("dd");
  dd.textContent = typeof value === "string" ? value : JSON.stringify(value);
  parent.appendChild(dt);
  parent.appendChild(dd);
}

function renderVerification(results) {
  verificationList.innerHTML = "";
  if (results.length === 0) {
    const li = document.createElement("li");
    li.innerHTML = `<span class="path">(no files listed in manifest)</span>`;
    verificationList.appendChild(li);
  } else {
    for (const r of results) {
      const li = document.createElement("li");
      const path = document.createElement("span");
      path.className = "path";
      path.textContent = r.path || "(unnamed)";
      const result = document.createElement("span");
      result.className = `result ${r.ok ? "ok" : "err"}`;
      if (r.ok) {
        result.textContent = "✓ sha256 match";
      } else if (r.actual === null) {
        result.textContent = "✗ blob missing";
      } else {
        result.textContent = `✗ ${shortHash(r.actual)} ≠ ${shortHash(r.expected)}`;
      }
      li.appendChild(path);
      li.appendChild(result);
      verificationList.appendChild(li);
    }
  }
  verificationView.classList.remove("hidden");
}

function renderDecisions(decisions) {
  decisionsTbody.innerHTML = "";
  if (!Array.isArray(decisions) || decisions.length === 0) {
    decisionsView.classList.add("hidden");
    return;
  }
  for (const d of decisions) {
    const tr = document.createElement("tr");

    const seq = document.createElement("td");
    seq.textContent = d.sequence ?? d.seq ?? "—";

    const actor = document.createElement("td");
    actor.textContent = d.actor || d.principal || d.principal_id || "—";

    const tool = document.createElement("td");
    tool.textContent = d.tool || d.tool_name || d.action || "—";

    const verdictRaw = (d.verdict || d.decision || "").toString().toUpperCase();
    const verdict = document.createElement("td");
    const v = document.createElement("span");
    v.className = "verdict " + verdictClass(verdictRaw);
    v.textContent = verdictRaw || "—";
    verdict.appendChild(v);

    const reason = document.createElement("td");
    reason.textContent = d.reason_code || d.reason || "";

    tr.appendChild(seq);
    tr.appendChild(actor);
    tr.appendChild(tool);
    tr.appendChild(verdict);
    tr.appendChild(reason);
    decisionsTbody.appendChild(tr);
  }
  decisionsView.classList.remove("hidden");
}

function verdictClass(v) {
  if (v === "ALLOW" || v === "APPROVED" || v === "PERMIT") return "allow";
  if (v === "DENY" || v === "DENIED" || v === "REJECTED") return "deny";
  if (v === "ESCALATE" || v === "REQUIRE_APPROVAL") return "escalate";
  return "";
}

function setStatus(kind, text) {
  statusEl.className = `status ${kind}`;
  statusEl.textContent = text;
  statusEl.classList.remove("hidden");
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

function shortHash(h) {
  if (!h) return "(none)";
  const s = String(h).replace(/^sha256:/i, "");
  return s.length > 16 ? s.slice(0, 8) + "…" + s.slice(-4) : s;
}
