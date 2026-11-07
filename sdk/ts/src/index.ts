export { HelmClient, HelmApiError } from "./client.js";
export type {
  HelmClientConfig,
  ReasonCode,
  HelmError,
  EvidenceEnvelopeExportRequest,
  EvidenceEnvelopeManifest,
  EvidenceEnvelopePayload,
  ApprovalCeremony,
  ApprovalWebAuthnAssertion,
  ApprovalWebAuthnChallenge,
  BoundaryCheckpoint,
  GovernanceMetadata,
  ChatCompletionWithReceipt,
  EvaluateDecisionRequest,
  EvaluateDecisionResponse,
  McpQuarantineRecord,
  McpRegistryDiscoverRequest,
  NegativeBoundaryVector,
  SandboxBackendProfile,
  SandboxGrant,
  SurfaceRecord,
} from "./client.js";
export type {
  ChatCompletionRequest,
  ChatCompletionResponse,
  ApprovalRequest,
  Receipt,
  Session,
  VerificationResult,
  ConformanceRequest,
  ConformanceResult,
  VersionInfo,
  ExportRequest,
} from "./types.gen.js";

export { ReasonCodes, isRegisteredReasonCode } from "./reason_codes.gen.js";
export type { RegisteredReasonCode } from "./reason_codes.gen.js";

export {
  NATIVE_GATEWAY_PROTOCOL_VERSION,
  NativeGatewayClient,
  NativeGatewayError,
} from "./adapters/native-gateway.js";
export type {
  NativeGatewayConfig,
  NativeGatewayEffect,
  NativeGatewayOutcome,
  NativeGatewayRequestOptions,
  NativeGatewayStatus,
  NativeGatewayTool,
  NativeGatewayToolResult,
} from "./adapters/native-gateway.js";
