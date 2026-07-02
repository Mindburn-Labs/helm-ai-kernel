#!/usr/bin/env python3

from __future__ import annotations

import unittest

import validate_workflow_dispatch_inputs as validator


class WorkflowDispatchInputValidationTest(unittest.TestCase):
    def test_publish_version_accepts_semver(self) -> None:
        self.assertEqual(validator.validate_version("1.2.3"), "1.2.3")
        self.assertEqual(validator.validate_version("1.2.3-rc.1"), "1.2.3-rc.1")

    def test_publish_version_rejects_shell_metacharacters(self) -> None:
        for value in ["v1.2.3", "1.2.3;echo pwned", "1.2.3$(id)", "1.2.3\nX=1"]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validator.validate_version(value)

    def test_publish_release_tag_must_match_version(self) -> None:
        self.assertIsNone(validator.validate_optional_publish_tag("", version="1.2.3"))
        self.assertEqual(validator.validate_optional_publish_tag("v1.2.3", version="1.2.3"), "v1.2.3")
        for tag in ["v1.2.4", "1.2.3", "v1.2.3;echo pwned"]:
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    validator.validate_optional_publish_tag(tag, version="1.2.3")

    def test_bool_is_strict(self) -> None:
        self.assertTrue(validator.validate_bool("true", field="dry_run"))
        self.assertFalse(validator.validate_bool("false", field="dry_run"))
        with self.assertRaises(ValueError):
            validator.validate_bool("yes", field="dry_run")

    def test_clean_install_inputs_are_tightly_scoped(self) -> None:
        self.assertEqual(validator.validate_release_tag("v1.2.3"), "v1.2.3")
        self.assertEqual(validator.validate_artifact_run_id("26198407296"), "26198407296")
        for tag in ["1.2.3", "v1.2.3;echo pwned", "v1.2"]:
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    validator.validate_release_tag(tag)
        for run_id in ["0", "12345", "123;echo pwned", "abc"]:
            with self.subTest(run_id=run_id):
                with self.assertRaises(ValueError):
                    validator.validate_artifact_run_id(run_id)


if __name__ == "__main__":
    unittest.main()
