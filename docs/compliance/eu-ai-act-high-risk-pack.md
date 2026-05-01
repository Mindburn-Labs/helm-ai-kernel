---
title: EU AI Act High-Risk Pack
---

# EU AI Act High-Risk Pack

The HELM OSS EU AI Act reference pack is `reference_packs/eu_ai_act_high_risk.v1.json`.

## Source Status

Primary source verified on April 30, 2026: the European Commission AI Act Service Desk timeline says the majority of AI Act rules start applying on August 2, 2026, including Annex III high-risk AI system rules, Article 50 transparency rules, innovation-support measures, and national/EU-level enforcement.

The same source notes that high-risk AI embedded in regulated products applies on August 2, 2027. The reference pack therefore distinguishes:

- `high_risk_full`: `2026-08-02`
- `high_risk_annex_i`: `2027-08-02`

## Pack Coverage

The pack maps HELM evidence requirements and policy rules to:

- Article 9 risk management;
- Article 11 technical documentation;
- Article 13 transparency;
- Article 14 human oversight;
- Annex III high-risk deployment areas.

The April 2026 MCP update also records two evidence requirements relevant to high-risk agent deployments:

- `oauth_resource_binding`: bearer tokens used at the MCP gateway are checked against the intended resource indicator;
- `tool_scope_enforcement`: per-tool scopes can be exposed in MCP metadata and enforced before execution.

These requirements complement, but do not replace, receipt signing, ProofGraph verification, AI-BOM availability, conformity-assessment evidence, and QTSP timestamp anchoring.
