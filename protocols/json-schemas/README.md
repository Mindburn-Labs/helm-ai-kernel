# JSON Schemas Source Owner

## Audience

Use this file when changing protocol JSON Schemas, adding receipt/evidence schema coverage, or updating examples that claim schema compatibility.

## Responsibility

`protocols/json-schemas` owns normative JSON Schema files used by public references, conformance checks, and generated examples. Public docs summarize schema families; this directory owns concrete field-level contracts.

## Documentation Contract

- Public reference hub: `helm-oss/reference/protocols-and-schemas`.
- Conformance route: `helm-oss/conformance`.
- Inventory row: `api-protocols-schemas` in `docs/source-inventory.manifest.json`.

Do not document a schema field as stable unless the schema file and at least one validation or conformance path prove it.
