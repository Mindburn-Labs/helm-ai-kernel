// proofgraph.js — render ProofGraph nodes as a causal tree.
//
// Nodes are expected to follow HELM's ProofGraph shape (from core/pkg/proofgraph):
//   {
//     id: string,
//     type: "INTENT" | "ATTESTATION" | "EFFECT" | "TRUST_EVENT" | "CHECKPOINT" | "MERGE_DECISION" | "ZK_PROOF" | ...,
//     actor: string,
//     sequence: number,   // Lamport-ordered
//     parent_ids: [string, ...],   // causal parents
//     payload: object,
//     created_at: string (ISO8601),
//   }
//
// The renderer builds a simple indented tree with <details>/<summary>
// elements. Orphan nodes (no parents) are roots; each other node is nested
// under its first-listed parent.

/**
 * Render an array of ProofGraph nodes into a target element.
 * @param {HTMLElement} target
 * @param {Array<object>} nodes
 */
export function renderProofGraph(target, nodes) {
  target.innerHTML = "";
  if (!Array.isArray(nodes) || nodes.length === 0) {
    const p = document.createElement("p");
    p.className = "small";
    p.textContent = "(no ProofGraph nodes in this pack)";
    target.appendChild(p);
    return;
  }

  // Sort by Lamport sequence for deterministic rendering
  const sorted = [...nodes].sort(
    (a, b) => (a.sequence ?? 0) - (b.sequence ?? 0),
  );

  // Build parent -> [children] map, ordered by sequence.
  const byId = new Map();
  const children = new Map();
  const roots = [];
  for (const n of sorted) {
    byId.set(n.id, n);
    children.set(n.id, []);
  }
  for (const n of sorted) {
    const parents = Array.isArray(n.parent_ids) ? n.parent_ids : [];
    if (parents.length === 0) {
      roots.push(n);
      continue;
    }
    // Use the first known parent as the rendering parent.
    const parentId = parents.find((pid) => byId.has(pid));
    if (parentId) {
      children.get(parentId).push(n);
    } else {
      roots.push(n); // orphan — treat as root
    }
  }

  for (const root of roots) {
    target.appendChild(renderNode(root, children));
  }
}

function renderNode(node, children) {
  const details = document.createElement("details");
  const summary = document.createElement("summary");

  const typeSpan = document.createElement("span");
  typeSpan.className = "ntype";
  typeSpan.textContent = node.type || "NODE";

  const rest = document.createElement("span");
  rest.textContent = ` · #${node.sequence ?? "?"} · ${node.actor || "?"} · ${shortId(node.id)}`;

  summary.appendChild(typeSpan);
  summary.appendChild(rest);
  details.appendChild(summary);

  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify(node, null, 2);
  details.appendChild(pre);

  const kids = children.get(node.id) || [];
  for (const child of kids) {
    details.appendChild(renderNode(child, children));
  }

  return details;
}

function shortId(id) {
  if (!id) return "(no id)";
  const s = String(id);
  return s.length > 16 ? s.slice(0, 8) + "…" + s.slice(-4) : s;
}
