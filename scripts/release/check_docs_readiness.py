#!/usr/bin/env python3
"""Require a working release-backed docs origin before immutable publication.

This checks the existing release, not the candidate's post-release acceptance.
"""
import json
import re
import subprocess
import urllib.parse
import urllib.request

ORIGIN = "https://helm.docs.mindburn.org"


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl)[:2] != urllib.parse.urlsplit(ORIGIN)[:2]:
            raise ValueError(f"docs redirect leaves public HTTPS origin: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(path):
    request = urllib.request.Request(
        ORIGIN + path, headers={"User-Agent": "helm-release-preflight/1.0"})
    with urllib.request.build_opener(SameOriginRedirect()).open(request, timeout=30) as response:
        if response.status != 200:
            raise ValueError(f"docs {path}: HTTP {response.status}")
        return response.read().decode("utf-8")


def validate_metadata(metadata, resolve_tag):
    if not isinstance(metadata, dict) or metadata.get("publication") != "release":
        raise ValueError("public docs must expose release publication metadata")
    for key in ("sha", "kernelCommit"):
        if not re.fullmatch(r"[0-9a-f]{40}", str(metadata.get(key, ""))):
            raise ValueError(f"invalid public docs {key}")
    tag = metadata.get("kernelTag", "")
    if not isinstance(tag, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("invalid public docs kernelTag")
    if not re.fullmatch(r"[1-9][0-9]*", str(metadata.get("runId", ""))):
        raise ValueError("invalid public docs publication runId")
    if resolve_tag(tag) != metadata["kernelCommit"]:
        raise ValueError("public docs tag does not resolve to its claimed source")


def resolve_tag(tag):
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"], text=True).strip()
    subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"], check=True)
    return commit


def main():
    metadata = json.loads(fetch("/version.json"))
    validate_metadata(metadata, resolve_tag)
    # Links in the exported docs omit trailing slashes. Following them also
    # tests that the proxy's private port/scheme cannot escape via Location.
    for path in ("/developer-journey", "/sdks", "/examples"):
        if metadata["kernelTag"][1:] not in fetch(path):
            raise ValueError(f"docs {path} does not match publication metadata")
    print(json.dumps({"docs_readiness": "pass", "publication": metadata}, indent=2))


if __name__ == "__main__":
    main()
