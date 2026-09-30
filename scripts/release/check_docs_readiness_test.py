#!/usr/bin/env python3
import unittest
import urllib.request
from check_docs_readiness import ORIGIN, SameOriginRedirect, validate_metadata


class DocsReadinessTest(unittest.TestCase):
    def setUp(self):
        self.metadata = dict(publication="release", sha="a" * 40,
                             kernelCommit="b" * 40, kernelTag="v0.10.2", runId="123")

    def test_release_metadata_resolves_to_source(self):
        validate_metadata(self.metadata, lambda tag: "b" * 40)

    def test_legacy_preview_and_malformed_metadata_fail(self):
        for value in ({}, None, {**self.metadata, "publication": "preview"},
                      {**self.metadata, "sha": "main"},
                      {**self.metadata, "kernelTag": "main"},
                      {**self.metadata, "runId": ""}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_metadata(value, lambda tag: "b" * 40)

    def test_wrong_source_fails(self):
        with self.assertRaises(ValueError):
            validate_metadata(self.metadata, lambda tag: "c" * 40)

    def test_redirects_preserve_https_authority(self):
        handler = SameOriginRedirect()
        request = urllib.request.Request(ORIGIN + "/sdks")
        self.assertEqual(handler.redirect_request(request, None, 301, "", {},
                         ORIGIN + "/sdks/").full_url, ORIGIN + "/sdks/")
        for target in (ORIGIN + ":8080/sdks/", "http://helm.docs.mindburn.org/sdks/",
                       "https://other.example/sdks/"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 301, "", {}, target)


if __name__ == "__main__":
    unittest.main()
