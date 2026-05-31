# BGT Labs Sentinel Interoperability Adapter

> Status: integration-certified. This adapter certifies the integration of BGT Labs Sentinel universal auth proposals within the HELM AI Kernel gateway.

HELM integrates with BGT Labs Sentinel via the `SentinelConnector` to ingest external execution proposals and yield offline-verifiable cryptographic execution receipts. By serving as an authorization gateway, HELM bridges universal intent formats with fine-grained local Cedar policy enforcement.

## Gateway Middleware & Intent Mapping

The integration is driven by `SentinelConnector` under `core/pkg/mcp/sentinel.go`, which implements `http.Handler`:

1. **HTTP Endpoint Hosting**:
   The connector hosts a POST endpoint that parses BGT Labs Sentinel universal authorization proposals.
   
2. **Intent Parsing & Mapping**:
   Inbound proposals contain universal execution intent attributes (`principal`, `action`, `resource`, `context`). The connector maps these elements directly to a HELM `DecisionRequest`.

3. **Fine-Grained Policy Evaluation**:
   HELM's core `Guardian` evaluates the request against loaded active policies.

4. **Cryptographic Execution Receipts**:
   Decisions are cryptographically signed using HELM's offline-verifiable keys (Ed25519) and returned as a JSON-encoded decision record. This receipt serves as tamper-proof evidence that the execution was authorized in compliance with local organizational posture.

## Verification

To run integration smoke tests on the HTTP gateway:

```bash
cd core
go test ./pkg/mcp -run TestSentinelConnectorEvaluation -v
```

## Security Best Practices

- Always front the `SentinelConnector` HTTP endpoint with mutual TLS (mTLS) in production environments.
- Validate that Sentinel intent contexts include required ambient session metadata to prevent replay attacks.
- Ensure the gateway signer keys are securely loaded and managed via HSM or KMS.
