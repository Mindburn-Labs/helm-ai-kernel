---
title: IDENTITY_INTEROP
---

# Identity Interop

HELM is not an identity provider.

Identity systems answer:

- who is this principal?
- how was it authenticated?

HELM answers:

- is this side effect authorized under the current policy and scope?
- what proof exists for the allow or deny decision?

## Recommended split

- **OIDC / OAuth / SSO**: authenticate humans and services
- **SPIFFE / mTLS / workload identity**: authenticate runtime workloads
- **Teleport / bastion / session brokers**: broker privileged access
- **HELM**: enforce execution authority at the side-effect boundary

## Minimal metadata contract

When a trusted identity layer authenticates a principal, forward stable scope metadata into HELM receipts:

```json
{
  "organization_id": "acme-operations",
  "scope_id": "platform.prod.deploy",
  "principal_id": "devops_lead"
}
```

These fields are optional and backward-compatible. They make it possible to move from local agent governance toward organization-scoped execution without changing the kernel contract.

## W3C DID Support (`identity/did/`)

> *Added April 2026*

HELM supports W3C Decentralized Identifiers (DIDs) as a native identity format for agents. DIDs provide self-sovereign, cryptographically verifiable identity without dependence on a central authority.

When a DID is present, HELM:

1. **Resolves** the DID document to extract verification methods and service endpoints
2. **Validates** the DID signature on incoming requests against the resolved public key
3. **Binds** the DID to the execution receipt, creating a verifiable link between identity and action
4. **Maps** DID-based identity into the existing `principal_id` field for backward compatibility

DIDs complement (not replace) existing OIDC/SPIFFE flows. An operator can require DID-based identity for cross-organization interactions while keeping internal agents on OIDC.

## AIP Delegation (`mcp/aip.go`)

> *Added April 2026*

The Agent Identity Protocol (AIP) extends MCP with delegation semantics. When an agent delegates a task to an MCP tool server, AIP:

- Attaches a **delegation token** to the MCP request, scoped to the specific tool and action
- The MCP server can verify the delegation chain back to the originating principal
- Delegation scope is enforced by the PEP: the MCP server cannot exceed the delegated capabilities
- All delegation events are recorded in the ProofGraph

AIP is the MCP-layer equivalent of HELM's kernel delegation sessions, ensuring that the confused deputy problem is addressed at the protocol boundary.

## Continuous Delegation (`identity/continuous_delegation.go`)

> *Added April 2026*

AITH (Agent Identity and Trust Handshake) continuous delegation provides time-bound, revocable delegation sessions for long-running agent workflows:

- **Time-bound**: Delegation expires after a configurable TTL (default: 1 hour)
- **Revocable**: Operator can revoke a delegation at any time; revocation is propagated and receipted
- **Renewable**: Agents can request renewal before expiry; renewal is a new delegation (not an extension), preserving the audit trail
- **Scoped**: Each renewal can narrow (but never widen) the delegation scope

This is designed for agents that run continuously (e.g., monitoring, research, operations) where one-shot delegation sessions are impractical.
