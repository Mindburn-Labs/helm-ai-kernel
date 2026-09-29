"""The exact-price contract refuses legacy units and ambiguous free tariffs."""

import copy
import json
from pathlib import Path
import unittest

import jsonschema


class ProviderPriceSchemaTest(unittest.TestCase):
    def test_exact_price_and_closed_boundary(self):
        root = Path(__file__).resolve().parents[2] / "protocols/json-schemas/spend"
        schema = json.loads((root / "provider_price_snapshot.v2.schema.json").read_text())
        validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
        price = {
            "schema_version": "helm.provider-price-snapshot.v2", "id": "price-jev",
            "provider_id": "typesafe", "model_id": "jev-1.13.0", "currency": "USD",
            "input_token_nano_cents": 4200, "provider_terms_profile_id": "terms",
            "source_hash": "sha256:" + "a" * 64, "content_hash": "sha256:" + "b" * 64,
            "captured_at": "2026-09-29T00:00:00Z", "effective_at": "2026-09-29T00:00:00Z",
            "expires_at": "2026-09-29T01:00:00Z",
        }
        validator.validate(price)
        for field, value in [
            ("schema_version", "future"), ("input_token_micro_cents", 4),
            ("request_cents", 1), ("input_token_nano_cents", 0),
            ("input_token_nano_cents", -1), ("input_token_nano_cents", 4200.5),
            ("input_token_nano_cents", 2**63), ("source_hash", "unbound"),
            ("expires_at", "tomorrow"), ("unknown", True),
        ]:
            with self.subTest(field=field, value=value):
                invalid = {**price, field: value}
                self.assertFalse(validator.is_valid(invalid))
        missing_version = copy.deepcopy(price)
        del missing_version["schema_version"]
        self.assertFalse(validator.is_valid(missing_version))
        legacy_bundle = json.loads((root / "spend_authority_contracts.v1.schema.json").read_text())
        self.assertFalse(jsonschema.Draft202012Validator(legacy_bundle).is_valid(price))


if __name__ == "__main__":
    unittest.main()
