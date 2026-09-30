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
        # Shared with the Go producer's golden wire/digest test. These are
        # synthetic terms and source hashes, not captured provider evidence.
        fixture = Path(__file__).resolve().parents[2] / "core/pkg/contracts/economic/testdata/provider_price_v2.json"
        price = json.loads(fixture.read_text())
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
