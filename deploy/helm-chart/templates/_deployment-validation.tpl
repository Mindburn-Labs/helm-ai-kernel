{{/* quantum_posture: validates classical Ed25519 public key settings. */}}
{{- define "helm-ai-kernel.validateDeployment" -}}
{{- $ipv4Octet := "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])" -}}
{{- $controlPlaneLoopback := regexMatch (printf "(?i)^http://(localhost|127\\.%s\\.%s\\.%s|\\[[0:]*1\\]|\\[[0:]*ffff:(127\\.%s\\.%s\\.%s|7f[0-9a-f]{2}:[0-9a-f]{1,4})\\])(:[0-9]+)?(/|$)" $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet) .Values.helm.policy.source.controlplane.url -}}
{{- if not (or (eq .Values.helm.policy.source.kind "controlplane") (eq .Values.helm.policy.source.kind "crd") (eq .Values.helm.policy.source.kind "mountedFile")) -}}
{{- fail "helm.policy.source.kind must be one of controlplane, crd, mountedFile" -}}
{{- end -}}
{{- if and .Values.helm.production (not .Values.persistence.enabled) -}}
{{- fail "helm.production=true requires persistence.enabled=true for durable policy replay protection" -}}
{{- end -}}
{{- if and .Values.helm.production (ne (int .Values.replicaCount) 1) -}}
{{- fail "helm.production=true requires replicaCount=1 until policy replay state has a distributed store" -}}
{{- end -}}
{{- if and .Values.helm.production (eq .Values.helm.policy.source.kind "mountedFile") -}}
{{- fail "helm.production=true rejects helm.policy.source.kind=mountedFile because filesystem timestamps are not source-owned monotonic publication epochs; use controlplane" -}}
{{- end -}}
{{- if and .Values.helm.production (eq .Values.helm.policy.source.kind "controlplane") (not .Values.helm.policy.source.controlplane.url) -}}
{{- fail "helm.production=true with helm.policy.source.kind=controlplane requires helm.policy.source.controlplane.url" -}}
{{- end -}}
{{- if and .Values.helm.production (eq .Values.helm.policy.source.kind "controlplane") (not $controlPlaneLoopback) (not (regexMatch "^https://" .Values.helm.policy.source.controlplane.url)) -}}
{{- fail "helm.production=true requires an https helm.policy.source.controlplane.url except for an in-Pod loopback fixture" -}}
{{- end -}}
{{- if and .Values.helm.production (eq .Values.helm.policy.source.kind "controlplane") (not $controlPlaneLoopback) (not .Values.helm.policy.source.controlplane.tls.existingSecret) -}}
{{- fail "helm.production=true with a controlplane policy source requires helm.policy.source.controlplane.tls.existingSecret for exclusive CA trust" -}}
{{- end -}}
{{- if and .Values.helm.policy.source.controlplane.tls.existingSecret (not .Values.helm.policy.source.controlplane.tls.existingSecretKey) -}}
{{- fail "helm.policy.source.controlplane.tls.existingSecretKey is required when a TLS CA Secret is configured" -}}
{{- end -}}
{{- if and (eq .Values.helm.policy.source.kind "controlplane") (not (or (eq .Values.helm.policy.source.controlplane.auth.mode "serviceAccountJWT") (eq .Values.helm.policy.source.controlplane.auth.mode "bearerToken"))) -}}
{{- fail "controlplane auth mode must be serviceAccountJWT or bearerToken" -}}
{{- end -}}
{{- if and (eq .Values.helm.policy.source.kind "controlplane") (eq .Values.helm.policy.source.controlplane.auth.mode "serviceAccountJWT") (not .Values.helm.policy.source.controlplane.auth.serviceAccountJWT.audience) -}}
{{- fail "controlplane serviceAccountJWT auth requires a non-empty audience" -}}
{{- end -}}
{{- if and (eq .Values.helm.policy.source.kind "controlplane") (eq .Values.helm.policy.source.controlplane.auth.mode "serviceAccountJWT") (or .Values.helm.policy.source.controlplane.auth.bearerToken .Values.helm.policy.source.controlplane.auth.existingSecret) -}}
{{- fail "controlplane serviceAccountJWT auth cannot also configure a static bearer token" -}}
{{- end -}}
{{- if and (eq .Values.helm.policy.source.kind "controlplane") (eq .Values.helm.policy.source.controlplane.auth.mode "bearerToken") (not (or .Values.helm.policy.source.controlplane.auth.bearerToken .Values.helm.policy.source.controlplane.auth.existingSecret)) -}}
{{- fail "controlplane bearerToken auth requires helm.policy.source.controlplane.auth.bearerToken or existingSecret" -}}
{{- end -}}
{{- if and .Values.helm.policy.signature.publicKey (not (regexMatch "^[0-9a-fA-F]{64}$" .Values.helm.policy.signature.publicKey)) -}}
{{- fail "helm.policy.signature.publicKey must be a 64-character hex Ed25519 public key" -}}
{{- end -}}
{{- with .Values.helm.auth.controlPlaneActivationPublicKey -}}
{{- if not (regexMatch "^[0-9a-f]{64}$" .) -}}
{{- fail "helm.auth.controlPlaneActivationPublicKey must be a 64-character lowercase hex Ed25519 public key" -}}
{{- end -}}
{{- if not (and $.Values.helm.auth.existingSecret $.Values.helm.auth.organizationRuntimeAPIKeySecretKey) -}}
{{- fail "helm.auth.controlPlaneActivationPublicKey requires the organization-runtime key (helm.auth.existingSecret and helm.auth.organizationRuntimeAPIKeySecretKey): the Kernel needs HELM_CONTROL_PLANE_ACTIVATION_PUBLIC_KEY and HELM_ORGANIZATION_RUNTIME_API_KEY together" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.helm.policy.signature.required (not (or .Values.helm.policy.signature.publicKey .Values.helm.policy.signature.existingSecret)) -}}
{{- fail "helm.policy.signature.required=true requires helm.policy.signature.publicKey or helm.policy.signature.existingSecret" -}}
{{- end -}}
{{- if and .Values.helm.production (eq .Values.helm.policy.source.kind "controlplane") (not .Values.helm.policy.signature.required) -}}
{{- fail "helm.production=true with helm.policy.source.kind=controlplane requires helm.policy.signature.required=true" -}}
{{- end -}}
{{- if and .Values.helm.production (not .Values.helm.policy.agentSafety.baseline.enabled) -}}
{{- fail "helm.production=true requires helm.policy.agentSafety.baseline.enabled=true" -}}
{{- end -}}
{{- if and .Values.helm.production (or (not .Values.helm.policy.agentSafety.denyUnknownTools) (not .Values.helm.policy.agentSafety.denyUnknownEgress) (not .Values.helm.policy.agentSafety.requireManifestValidation) (not .Values.helm.policy.agentSafety.requireOutputContractValidation) (not .Values.helm.policy.agentSafety.requireApprovedArgBinding) (not .Values.helm.policy.agentSafety.lksMemoryInfluenceOnly) (not .Values.helm.policy.agentSafety.requireA2ASignatures) (not .Values.helm.policy.agentSafety.enforceSafeDepGates) (not .Values.helm.policy.agentSafety.enforceBudgetCircuitBreakers) (not .Values.helm.policy.agentSafety.failClosedOnMissingContext)) -}}
{{- fail "helm.production=true requires all helm.policy.agentSafety fail-closed guards enabled" -}}
{{- end -}}
{{- if and .Values.helm.production (eq .Values.helm.storage.type "postgres") (not .Values.helm.storage.postgres.existingSecret) -}}
{{- fail "helm.production=true with helm.storage.type=postgres requires helm.storage.postgres.existingSecret; inline database credentials are not rendered into Deployments" -}}
{{- end -}}
{{- if and .Values.helm.production (eq .Values.helm.storage.type "postgres") .Values.postgresql.enabled -}}
{{- fail "helm.production=true with helm.storage.type=postgres does not support the bundled postgresql subchart; provide an external TLS DATABASE_URL via helm.storage.postgres.existingSecret" -}}
{{- end -}}
{{- if and .Values.helm.production (eq .Values.helm.storage.type "postgres") (not (or (eq .Values.helm.storage.postgres.sslMode "require") (eq .Values.helm.storage.postgres.sslMode "verify-ca") (eq .Values.helm.storage.postgres.sslMode "verify-full"))) -}}
{{- fail "helm.production=true with helm.storage.type=postgres requires helm.storage.postgres.sslMode=require, verify-ca, or verify-full" -}}
{{- end -}}
{{- if and .Values.helm.production (not .Values.helm.auth.tenantID) -}}
{{- fail "helm.production=true requires helm.auth.tenantID so tenant-scoped runtime routes are server-bound" -}}
{{- end -}}
{{- if and .Values.helm.production (not .Values.helm.auth.principalID) -}}
{{- fail "helm.production=true requires helm.auth.principalID so tenant-scoped runtime routes are server-bound" -}}
{{- end -}}
{{- if and .Values.helm.emergencyStop.enabled (not .Values.helm.auth.workspaceID) -}}
{{- fail "helm.emergencyStop.enabled=true requires helm.auth.workspaceID so scoped dispatches are server-bound" -}}
{{- end -}}
{{- if and .Values.helm.emergencyStop.enabled (not .Values.helm.emergencyStop.audience) -}}
{{- fail "helm.emergencyStop.enabled=true requires helm.emergencyStop.audience" -}}
{{- end -}}
{{- if and .Values.helm.emergencyStop.enabled (not (or .Values.helm.emergencyStop.commandPublicKeys .Values.helm.emergencyStop.existingSecret)) -}}
{{- fail "helm.emergencyStop.enabled=true requires helm.emergencyStop.commandPublicKeys or helm.emergencyStop.existingSecret" -}}
{{- end -}}
{{- if and .Values.helm.emergencyStop.enabled .Values.helm.emergencyStop.commandReplayKeyring .Values.helm.emergencyStop.commandReplayKeyringSecretKey -}}
{{- fail "helm.emergencyStop.commandReplayKeyring and commandReplayKeyringSecretKey are mutually exclusive" -}}
{{- end -}}
{{- if and .Values.helm.emergencyStop.enabled .Values.helm.emergencyStop.commandReplayKeyringSecretKey (not .Values.helm.emergencyStop.existingSecret) -}}
{{- fail "helm.emergencyStop.commandReplayKeyringSecretKey requires helm.emergencyStop.existingSecret" -}}
{{- end -}}
{{- if and .Values.telemetry.syntheticLifecycleEvents (not .Values.telemetry.enabled) -}}
{{- fail "telemetry.syntheticLifecycleEvents=true requires telemetry.enabled=true" -}}
{{- end -}}
{{- if and (eq .Values.telemetry.metricsExporter "otlp") (not .Values.telemetry.enabled) -}}
{{- fail "telemetry.metricsExporter=otlp requires telemetry.enabled=true" -}}
{{- end -}}
{{- if and .Values.helm.githubEffects.apiURL (not .Values.helm.githubEffects.existingSecret) -}}
{{- fail "helm.githubEffects.apiURL requires helm.githubEffects.existingSecret" -}}
{{- end -}}
{{- if and .Values.helm.tls.clientAuth (not .Values.helm.tls.existingSecret) -}}
{{- fail "helm.tls.clientAuth requires helm.tls.existingSecret, whose ca.crt is the client CA" -}}
{{- end -}}
{{- if and .Values.helm.tls.existingSecret .Values.helm.policy.reloadHints.enabled .Values.helm.policy.reloadHints.configReloaderSidecar.enabled -}}
{{- fail "helm.tls.existingSecret cannot be combined with the config-reloader sidecar, which wakes the API listener over plain HTTP" -}}
{{- end -}}
{{- if not (regexMatch "^.+@sha256:[0-9a-f]{64}$" .Values.runtimeInit.image) -}}
{{- fail "runtimeInit.image must be pinned by immutable sha256 digest" -}}
{{- end -}}
{{- end -}}
