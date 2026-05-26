# Operations Runbook: helm-ai-kernel Core Daemon

This runbook outlines operational procedures, troubleshooting steps, and fail-closed configurations for the HELM core daemon.

## Diagnostic Steps
* Check local daemon status:
  ```bash
  helm-ai-kernel status
  ```
* Stream runtime audit traces:
  ```bash
  helm-ai-kernel tail -f audit.log
  ```

## Emergency Troubleshooting
* **Symptom**: Daemon enters fail-closed deadlock and rejects all agent inputs.
* **Resolution**: Verify Kyverno/OPA policies have not been corrupted in the policy cache. Reload policies by executing:
  ```bash
  helm-ai-kernel reload-policies
  ```
* **Symptom**: Out of Memory (OOM) on high-throughput analytical loops.
* **Resolution**: Enforce resource limits inside the sandbox supervisor config, restart daemon, and confirm telemetry metrics are flowing.
