#!/usr/bin/env python3
"""Known-good and known-bad SQL for the migration safety check."""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from check_migrations import destructive  # noqa: E402


class DestructiveStatementTest(unittest.TestCase):
    def test_data_destroying_statements_are_flagged(self) -> None:
        for sql in (
            "DROP TABLE receipts;",
            "drop table if exists receipts cascade;",
            "ALTER TABLE receipts DROP COLUMN signature;",
            "TRUNCATE receipts;",
            "DROP SCHEMA helm CASCADE;",
            "DELETE FROM receipts WHERE true;",
            # An object dropped and never recreated is a real loss.
            "DROP POLICY IF EXISTS tenant_isolation ON receipts;",
            "DROP TRIGGER IF EXISTS t ON receipts;\nCREATE TRIGGER other BEFORE INSERT ON receipts FOR EACH ROW EXECUTE FUNCTION f();",
        ):
            with self.subTest(sql=sql):
                self.assertTrue(destructive(sql))

    def test_object_recreation_is_not_flagged(self) -> None:
        for sql in (
            "DROP TRIGGER IF EXISTS t ON receipts;\nCREATE TRIGGER t BEFORE INSERT ON receipts FOR EACH ROW EXECUTE FUNCTION f();",
            "DROP FUNCTION IF EXISTS f();\nCREATE OR REPLACE FUNCTION f() RETURNS int LANGUAGE sql AS 'select 1';",
            "DROP INDEX IF EXISTS receipts_by_tenant;\nCREATE UNIQUE INDEX IF NOT EXISTS receipts_by_tenant ON receipts (tenant_id);",
            "DROP POLICY IF EXISTS tenant_isolation ON receipts;\nCREATE POLICY tenant_isolation ON receipts USING (true);",
        ):
            with self.subTest(sql=sql):
                self.assertEqual(destructive(sql), [])


if __name__ == "__main__":
    unittest.main()
