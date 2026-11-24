{{- define "helm-ai-kernel.deploymentPolicyEnv" -}}
- name: HELM_POLICY_SOURCE_KIND
  value: {{ .Values.helm.policy.source.kind | quote }}
- name: HELM_POLICY_POLL_INTERVAL
  value: {{ .Values.helm.policy.source.pollInterval | quote }}
- name: HELM_POLICY_INITIAL_RECONCILE_TIMEOUT
  value: {{ .Values.helm.policy.source.initialReconcileTimeout | quote }}
- name: HELM_POLICY_ON_INVALID_UPDATE
  value: {{ .Values.helm.policy.failClosed.onInvalidUpdate | quote }}
- name: HELM_POLICY_LAST_KNOWN_GOOD_MAX_AGE
  value: {{ .Values.helm.policy.failClosed.lastKnownGoodMaxAge | quote }}
- name: HELM_POLICY_RELOAD_ENDPOINT
  value: {{ .Values.helm.policy.reloadHints.httpWakeEndpoint | quote }}
- name: HELM_POLICY_SIGNATURE_REQUIRED
  value: {{ ternary "1" "0" .Values.helm.policy.signature.required | quote }}
- name: HELM_AGENT_SAFETY_BASELINE_ENABLED
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.baseline.enabled | quote }}
- name: HELM_AGENT_SAFETY_BASELINE_BUNDLE_ID
  value: {{ .Values.helm.policy.agentSafety.baseline.bundleID | quote }}
- name: HELM_AGENT_SAFETY_DENY_UNKNOWN_TOOLS
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.denyUnknownTools | quote }}
- name: HELM_AGENT_SAFETY_DENY_UNKNOWN_EGRESS
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.denyUnknownEgress | quote }}
- name: HELM_AGENT_SAFETY_REQUIRE_MANIFEST_VALIDATION
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.requireManifestValidation | quote }}
- name: HELM_AGENT_SAFETY_REQUIRE_OUTPUT_CONTRACT_VALIDATION
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.requireOutputContractValidation | quote }}
- name: HELM_AGENT_SAFETY_REQUIRE_APPROVED_ARG_BINDING
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.requireApprovedArgBinding | quote }}
- name: HELM_AGENT_SAFETY_LKS_INFLUENCE_ONLY
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.lksMemoryInfluenceOnly | quote }}
- name: HELM_AGENT_SAFETY_REQUIRE_A2A_SIGNATURES
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.requireA2ASignatures | quote }}
- name: HELM_AGENT_SAFETY_ENFORCE_SAFEDEP_GATES
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.enforceSafeDepGates | quote }}
- name: HELM_AGENT_SAFETY_ENFORCE_BUDGET_CIRCUIT_BREAKERS
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.enforceBudgetCircuitBreakers | quote }}
- name: HELM_AGENT_SAFETY_FAIL_CLOSED_ON_MISSING_CONTEXT
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.failClosedOnMissingContext | quote }}
- name: HELM_AGENT_SAFETY_SHADOW_MODE_OBSERVES_ONLY
  value: {{ ternary "1" "0" .Values.helm.policy.agentSafety.shadowModeObservesOnly | quote }}
{{- if or .Values.helm.policy.signature.publicKey .Values.helm.policy.signature.existingSecret }}
- name: HELM_POLICY_TRUST_PUBLIC_KEY
  {{- if .Values.helm.policy.signature.existingSecret }}
  valueFrom:
    secretKeyRef:
      name: {{ .Values.helm.policy.signature.existingSecret }}
      key: {{ .Values.helm.policy.signature.existingSecretKey }}
  {{- else }}
  value: {{ .Values.helm.policy.signature.publicKey | quote }}
  {{- end }}
{{- end }}
{{- if eq .Values.helm.policy.source.kind "controlplane" }}
- name: HELM_POLICY_CONTROLPLANE_URL
  value: {{ .Values.helm.policy.source.controlplane.url | quote }}
{{- if .Values.helm.policy.source.controlplane.tls.existingSecret }}
- name: HELM_POLICY_CONTROLPLANE_CA_FILE
  value: "/var/run/secrets/helm-policy-controlplane-tls/ca.pem"
{{- end }}
- name: HELM_POLICY_CONTROLPLANE_AUTH_MODE
  value: {{ .Values.helm.policy.source.controlplane.auth.mode | quote }}
{{- if eq .Values.helm.policy.source.controlplane.auth.mode "serviceAccountJWT" }}
- name: HELM_POLICY_SERVICE_ACCOUNT_TOKEN_FILE
  value: "/var/run/secrets/helm-policy/token"
{{- end }}
{{- if or .Values.helm.policy.source.controlplane.auth.bearerToken .Values.helm.policy.source.controlplane.auth.existingSecret }}
- name: HELM_POLICY_BEARER_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ default (printf "%s-policy-controlplane" (include "helm-ai-kernel.fullname" .)) .Values.helm.policy.source.controlplane.auth.existingSecret }}
      key: {{ .Values.helm.policy.source.controlplane.auth.existingSecretKey }}
{{- end }}
{{- end }}
{{- if eq .Values.helm.policy.source.kind "crd" }}
- name: HELM_POLICY_CRD_API_GROUP
  value: {{ .Values.helm.policy.source.crd.apiGroup | quote }}
- name: HELM_POLICY_CRD_RESOURCE
  value: {{ .Values.helm.policy.source.crd.resource | quote }}
{{- end }}
{{- end -}}
