# Vaultak Interoperability Adapter

> Status: production-ready. This adapter certifies the integration between Vaultak transaction boundaries and the HELM Warm Sandbox Leasing subsystem.

HELM integrates with Vaultak to bind isolated sandboxed runners to transactional undo logs. By linking runner lifecycles directly to Vaultak transaction IDs, HELM guarantees state reversibility and rapid execution rollback capability.

## Architecture & Reversibility Logic

The Vaultak implementation utilizes the `VaultakStateBridge` under `core/pkg/sandbox/vaultak.go`:

1. **Transactional Lease Binding**:
   When a tool execution or workspace lease is provisioned, the active `Runner` is registered and bound to a Vaultak transaction ID.
   
2. **Sub-5ms OverlayFS Reset Transactions**:
   Upon transaction abort, rollback, or workspace recycling, `RollbackTransaction` is invoked. It immediately releases the sandboxed runner back into the `WarmLeaseManager` pool.
   
3. **Sterile Recycle Sequence**:
   The `WarmLeaseManager` triggers an asynchronous OverlayFS reset. The runner's writable upper directory is pruned, and the filesystem is restored to its sterile base digest. This entire recycle transaction is highly optimized, executing in under 5 milliseconds to support fast-path interactive workloads.

## Verification

To verify the speed bounds and correct state rollback of the OverlayFS reset transactions:

```bash
cd core
go test ./pkg/sandbox -run TestVaultakOverlayRollbackSpeed -v
```

## Production Guidelines

To maintain sub-5ms latency and robust state separation:
- Ensure the underlying host kernel supports rapid OverlayFS mount/unmount operations.
- Do not run heavy I/O workloads during clean-up that could block filesystem sync locks.
- Monitor execution bounds via the Prometheus metrics exposed under the `sandbox_pool_recycle_latency_seconds` histogram.
