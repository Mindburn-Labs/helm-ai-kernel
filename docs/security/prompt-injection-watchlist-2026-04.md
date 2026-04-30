---
title: Prompt Injection Watchlist - April 2026
---

# Prompt Injection Watchlist - April 2026

This note records the source verification and implementation decision for the April 2026 HOSS radar items on upstream prompt-injection defenses. It is not a production commitment; HELM remains the deterministic downstream execution boundary.

## Source Verification

| Linear | Source | Verification | Decision |
| --- | --- | --- | --- |
| `MIN-237` | [AgentWatcher: A Rule-based Prompt Injection Monitor](https://arxiv.org/abs/2604.01194v1) | arXiv record exists, submitted April 1, 2026; title and authors match the radar text | Keep as watchlist/prototype material |
| `MIN-238` | [ICON: Indirect Prompt Injection Defense for Agents based on Inference-Time Correction](https://arxiv.org/abs/2602.20708v1) | arXiv record exists, submitted February 24, 2026; title and authors match the radar text | Keep as watchlist/prototype material |

## HELM Mapping

AgentWatcher is useful to evaluate because its rule-oriented framing can provide an explainable pre-filter before requests reach Guardian. A production implementation should live behind a policy toggle and emit evidence about which rule, source segment, and confidence threshold caused a short-circuit.

ICON is an inference-time defense. It is complementary to HELM, not a replacement for HELM: the model-layer probe may reduce compromised plans before they are proposed, while HELM still governs the downstream action boundary with policy, effect, delegation, and receipt evidence.

## No-Go Criteria

Do not merge either approach into the default path until:

- the implementation can run deterministically or preserve a deterministic evidence envelope around model-assisted decisions;
- benchmark fixtures show the false-positive impact on benign tool-use workflows;
- policy authors can disable the pre-filter without weakening HELM's existing Guardian gate;
- emitted evidence can be replayed or independently inspected during incident review.
