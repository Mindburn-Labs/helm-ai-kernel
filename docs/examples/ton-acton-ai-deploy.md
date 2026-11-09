# TON Acton AI Deploy Example

This sequence shows the flow helm-gateway supports for Acton: local checks, then
a testnet publish. Effect types are `ton.acton.*`; see `controls.yaml` CTL-061.

1. An agent writes a Tolk contract into its project in the tenant's workspace.
2. The agent proposes, in order, `ton.acton.contract.build`,
   `ton.acton.contract.check`, `ton.acton.contract.format_check` and
   `ton.acton.contract.test`, each with target `ton-acton:<project>`. These run
   only when the operator configured an isolation command, because Acton
   executes the project's files.
3. The gateway records a signed outcome receipt for each, with the typed
   `ton.acton.result.v1` result (exit code, output and its hashes).
4. The agent proposes `ton.acton.library.publish_testnet` with a `wallet_ref`, a
   `max_ton_spend` and expected effects. The gateway publishes with its own
   testnet wallet and reports SUCCEEDED only after the testnet RPC shows the
   transaction.
5. Proposing `ton.acton.script.testnet` is refused with
   `ERR_TON_TENANT_CODE_WITH_KEY_REFUSED`, and any mainnet operation with
   `ERR_TON_MAINNET_REFUSED`.
