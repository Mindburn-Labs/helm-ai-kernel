# TON Acton AI Deploy Example

This sequence shows the intended OSS flow using typed HELM Acton actions.

1. An agent generates a Tolk contract.
2. HELM runs:

```sh
connector.ton.acton.contract.build
connector.ton.acton.contract.check
connector.ton.acton.contract.format_check
connector.ton.acton.contract.test
```

3. HELM records Acton receipts with source, manifest, stdout/stderr, and build
   artifact hashes.
4. The agent proposes testnet deployment through
   `connector.ton.acton.script.testnet`.
5. HELM allows only if policy permits testnet broadcast and the request has a
   network grant, wallet ref, spend cap, sidecar script manifest, and expected
   effects.
6. The agent proposes mainnet deployment through
   `connector.ton.acton.script.mainnet`.
7. HELM returns `ESCALATE` with `ERR_TON_APPROVAL_CEREMONY_REQUIRED` until an
   approval ceremony reference is present.
8. After approval, HELM dispatches only the typed connector-built argv array.
9. The resulting EvidencePack is checked with:

```sh
helm verify pack <ton-acton-evidencepack>
helm replay --evidence <ton-acton-evidencepack> --verify
```

Expected receipts include `OK`, `ERR_TON_SPEND_CEILING_EXCEEDED`,
`ERR_TON_ACTON_GENERIC_MAINNET_SCRIPT_DENIED`,
`ERR_TON_APPROVAL_CEREMONY_REQUIRED`, and
`ERR_CONNECTOR_CONTRACT_DRIFT` depending on the scenario.
