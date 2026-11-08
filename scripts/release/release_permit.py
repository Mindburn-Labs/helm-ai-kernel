#!/usr/bin/env python3
"""Build the release-permit context and collect the two provider reviews.

The tag-driven release workflow (release.yml, job release-permit) runs this
before any publish job. It produces the inputs of `release-permit-verify`
(core/cmd/release-permit-verify), which reduces them with
core/pkg/releasepermit into a deterministic permit:

  context  writes the commit-bound context JSON the reducer expects.
  review   asks each reviewer in release/permit-reviewers.json (one Anthropic
           and one OpenAI model, both through OpenRouter) for a verdict on the
           release delta, and wraps each answer in the review envelope.

Model output is advisory. This script only checks that an answer has the
closed shape the reducer reads; the reducer decides. A missing secret, a
provider error, a truncated or malformed answer, or a model that was not the
one requested stops the run with a non-zero exit: nothing fails open.

`--fixtures DIR` replaces the HTTP call with recorded model answers so the
rehearsal can exercise the whole pipeline without spending. release.yml never
passes it, and release_workflow_contract_test.py fails if it ever does.

quantum_posture: this script binds SHA-256 digests and workflow identity for a
release gate; it implements no cryptographic primitive and makes no
post-quantum claim.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
REVIEWERS_PATH = ROOT / "release" / "permit-reviewers.json"
POLICY_PATH = ROOT / "release" / "permit-review-policy.md"
# The repository the release delta is read from; tests point it at a fixture.
REPO = ROOT
GATE_PROFILES_PATH = ROOT / "scripts" / "ci" / "quality-gates.json"

CONTEXT_SCHEMA = "mindburn.release-permit-context/v2"
REVIEW_SCHEMA = "mindburn.release-review/v1"
AUTHORITY_SCHEMA = "mindburn.release-authority/v1"
REVIEWERS_SCHEMA = "mindburn.release-permit-reviewers/v1"

SHA40 = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
RELEASE_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
WORKFLOW_REF = re.compile(r"^(?P<repo>[^/@]+/[^/@]+)/(?P<path>\.github/workflows/[^/@]+\.ya?ml)@(?P<ref>refs/.+)$")
SEVERITIES = ("P0", "P1", "P2", "P3")
MAX_FINDINGS = 200

# Paths whose changes decide whether a release is trustworthy come first, so a
# truncated patch still shows them.
PRIORITY_PATHSPECS = (
    ".github/",
    "scripts/release/",
    "scripts/ci/",
    "release/",
    "Makefile",
    "VERSION",
    "core/cmd/",
    "core/go.mod",
    "Dockerfile",
    "deploy/",
)
NOISE_PATHSPECS = (
    ":(exclude)*package-lock.json",
    ":(exclude)*go.sum",
    ":(exclude)*.lock",
    ":(exclude)*.svg",
    ":(exclude)*.png",
    ":(exclude)*.snap",
    ":(exclude)docs/**",
)

Fetch = Callable[[str, dict[str, str]], Any]


class PermitError(Exception):
    """Any condition that must stop the release permit from being issued."""


def die(message: str) -> "None":
    print(f"release_permit: {message}", file=sys.stderr)
    raise SystemExit(2)


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=REPO, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if result.returncode != 0:
        raise PermitError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def load_reviewers(path: Path = REVIEWERS_PATH) -> dict[str, Any]:
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("schema") != REVIEWERS_SCHEMA:
        raise PermitError("unsupported reviewers schema")
    reviewers = config.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) != 2:
        raise PermitError("exactly two reviewers are required")
    providers = set()
    for reviewer in reviewers:
        provider, model, route = reviewer.get("provider"), reviewer.get("model"), reviewer.get("openrouter_id")
        if not (isinstance(provider, str) and IDENTIFIER.match(provider) and isinstance(model, str) and IDENTIFIER.match(model)):
            raise PermitError("reviewer provider and model must be canonical lowercase identifiers")
        if route != f"{provider}/{model}":
            raise PermitError(f"openrouter_id for {provider}/{model} must be exactly provider/model")
        providers.add(provider)
    if len(providers) != 2:
        raise PermitError("the two reviewers must use distinct providers")
    for key in ("endpoint", "secret_env"):
        if not isinstance(config.get(key), str) or not config[key]:
            raise PermitError(f"reviewers config needs {key}")
    if not config["endpoint"].startswith("https://openrouter.ai/"):
        raise PermitError("reviews go through OpenRouter only")
    for key in ("max_prompt_bytes", "max_output_tokens", "request_timeout_seconds"):
        if not isinstance(config.get(key), int) or config[key] <= 0:
            raise PermitError(f"reviewers config needs a positive integer {key}")
    return config


# --------------------------------------------------------------------------
# context
# --------------------------------------------------------------------------

def previous_release_tag(commit: str, current_tag: str | None) -> tuple[str, str]:
    """The highest plain vX.Y.Z tag that is an ancestor of `commit`, other than its own."""
    names = git("tag", "--list", "v[0-9]*", "--merged", commit).split()
    candidates = []
    for name in names:
        match = RELEASE_TAG.match(name)
        if not match or name == current_tag:
            continue
        tag_commit = git("rev-parse", f"refs/tags/{name}^{{commit}}").strip()
        if tag_commit == commit:
            continue
        candidates.append((tuple(int(part) for part in match.groups()), name, tag_commit))
    if not candidates:
        raise PermitError("no earlier release tag is an ancestor of the tagged commit; there is no delta to review")
    _, name, tag_commit = max(candidates)
    return name, tag_commit


def merged_pull_request(repository: str, commit: str, base_branch: str, fetch: Fetch) -> int:
    """The pull request that merged `commit` into the base branch, or an error."""
    url = f"https://api.github.com/repos/{repository}/commits/{commit}/pulls?per_page=100"
    pulls = fetch(url, {"Accept": "application/vnd.github+json"})
    if not isinstance(pulls, list):
        raise PermitError("GitHub returned a malformed pull request list")
    for pull in pulls:
        if (
            isinstance(pull, dict)
            and pull.get("merged_at")
            and pull.get("merge_commit_sha") == commit
            and isinstance(pull.get("base"), dict)
            and pull["base"].get("ref") == base_branch
            and isinstance(pull.get("number"), int)
            and pull["number"] > 0
        ):
            return pull["number"]
    raise PermitError(f"no pull request merged {commit} into {base_branch}; a release commit must come from a merged pull request")


def github_fetch(url: str, headers: dict[str, str]) -> Any:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        raise PermitError("GITHUB_TOKEN is required to look up the pull request that merged the release commit")
    request = urllib.request.Request(url, headers={**headers, "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed https API host
            return json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise PermitError(f"GitHub API read failed: {exc}") from exc


def build_context(
    *,
    env: dict[str, str],
    commit: str,
    tag: str | None,
    fetch: Fetch,
    pull_request: int | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    repository = env.get("GITHUB_REPOSITORY", "")
    if not REPOSITORY.match(repository):
        raise PermitError("GITHUB_REPOSITORY is not set to owner/name")
    match = WORKFLOW_REF.match(env.get("GITHUB_WORKFLOW_REF", ""))
    if not match:
        raise PermitError("GITHUB_WORKFLOW_REF is not set to owner/name/.github/workflows/<file>@<ref>")
    try:
        run_id, run_attempt = int(env["GITHUB_RUN_ID"]), int(env["GITHUB_RUN_ATTEMPT"])
    except (KeyError, ValueError) as exc:
        raise PermitError("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT must be integers") from exc
    if not SHA40.match(commit):
        raise PermitError("the tagged commit is not a full lowercase SHA")

    tree = git("rev-parse", f"{commit}^{{tree}}").strip()
    base_name, base_sha = previous_release_tag(commit, tag)
    if pull_request is None:
        pull_request = merged_pull_request(repository, commit, "main", fetch)
    config = load_reviewers()

    # Fixed by the reducer: `event` must read pull_request, the reviewed change
    # is the release delta (previous release .. tagged commit), and the
    # authority workflow must not be the commit under review, so the workflow
    # binding names the previous release commit. The workflow that actually
    # ran is recorded in workflow_ref.
    return {
        "schema": CONTEXT_SCHEMA,
        "repository": repository,
        "event": "pull_request",
        "pull_request": pull_request,
        "base_ref": "refs/heads/main",
        "base_sha": base_sha,
        "head_sha": commit,
        "merge_sha": commit,
        "merge_tree_sha": tree,
        "workflow_repository": match["repo"],
        "workflow_path": match["path"],
        "workflow_ref": match["ref"],
        "workflow_sha": base_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "issued_at": (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "authority": {
            "schema": AUTHORITY_SCHEMA,
            "generation": 1,
            "kernel_sha": commit,
            "gate_profiles_sha256": sha256_hex(GATE_PROFILES_PATH.read_bytes()),
            "adversarial_corpus_sha256": sha256_hex(POLICY_PATH.read_bytes()),
            "parent": None,
        },
        "required_reviewers": [
            {"provider": r["provider"], "model": r["model"]} for r in config["reviewers"]
        ],
        "_previous_release": base_name,
    }


def encode_context(context: dict[str, Any]) -> bytes:
    public = {key: value for key, value in context.items() if not key.startswith("_")}
    return (json.dumps(public, indent=2, sort_keys=True) + "\n").encode("utf-8")


# --------------------------------------------------------------------------
# review
# --------------------------------------------------------------------------

def release_delta(context: dict[str, Any], max_bytes: int) -> str:
    base, head = context["base_sha"], context["head_sha"]
    log = "\n".join(git("log", "--no-merges", "--format=%h %s", f"{base}..{head}").splitlines()[:400])
    stat = git("diff", "--stat=160", base, head, "--", ".", *NOISE_PATHSPECS)[:30000]
    parts: list[str] = []
    used = 0
    omitted = False
    for group in (PRIORITY_PATHSPECS, None):
        if group is None:
            patch = git("diff", "--no-color", "-U3", base, head, "--", ".", *NOISE_PATHSPECS,
                        *(f":(exclude){p}" for p in PRIORITY_PATHSPECS))
        else:
            patch = git("diff", "--no-color", "-U3", base, head, "--", *group, *NOISE_PATHSPECS)
        room = max_bytes - used
        encoded = patch.encode("utf-8", errors="replace")
        if len(encoded) > room:
            patch = encoded[:max(room, 0)].decode("utf-8", errors="ignore")
            omitted = True
        parts.append(patch)
        used += len(patch.encode("utf-8", errors="replace"))
        if omitted:
            break
    note = "\nDELTA TRUNCATED: later files in the patch were omitted to fit the review budget.\n" if omitted else ""
    return (
        f"repository: {context['repository']}\n"
        f"release commit: {head}\ntree: {context['merge_tree_sha']}\n"
        f"previous release: {context.get('_previous_release', '')} ({base})\n"
        f"merged pull request: #{context['pull_request']}\n\n"
        f"<release_delta>\n## commits\n{log}\n\n## diffstat\n{stat}\n\n## patch\n{''.join(parts)}{note}</release_delta>\n"
    )


def openrouter_post(config: dict[str, Any], api_key: str, body: dict[str, Any]) -> dict[str, Any]:
    payload = json.dumps(body).encode("utf-8")
    last: Exception | None = None
    for attempt in range(3):
        request = urllib.request.Request(
            config["endpoint"],
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "X-Title": "HELM release permit",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=config["request_timeout_seconds"]) as response:  # noqa: S310
                return json.load(response)
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code not in (429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            last = exc
        time.sleep(5 * (attempt + 1))
    raise PermitError(f"provider call failed: {type(last).__name__}")


def parse_answer(content: str) -> dict[str, Any]:
    """Validate the closed shape of a model answer. The reducer judges it afterwards."""
    text = content.strip()
    fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    try:
        answer = json.loads(text)
    except ValueError as exc:
        raise PermitError("model answer is not one JSON object") from exc
    if not isinstance(answer, dict) or set(answer) != {"verdict", "findings"}:
        raise PermitError("model answer must have exactly the keys verdict and findings")
    if answer["verdict"] not in ("ALLOW", "DENY"):
        raise PermitError("model verdict must be ALLOW or DENY")
    findings = answer["findings"]
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise PermitError("model findings must be an array of at most 200 items")
    clean = []
    for item in findings:
        if not isinstance(item, dict) or not {"severity", "code", "summary"} <= set(item) or not set(item) <= {"severity", "code", "summary", "path", "line"}:
            raise PermitError("a finding has the wrong keys")
        if item["severity"] not in SEVERITIES or not all(isinstance(item[k], str) and item[k] for k in ("code", "summary")):
            raise PermitError("a finding has an invalid severity, code or summary")
        entry = {k: item[k] for k in ("severity", "code", "summary")}
        if "path" in item:
            if not isinstance(item["path"], str):
                raise PermitError("a finding path must be a string")
            entry["path"] = item["path"]
        if "line" in item:
            if isinstance(item["line"], bool) or not isinstance(item["line"], int) or item["line"] < 0:
                raise PermitError("a finding line must be a non-negative integer")
            if item["line"]:
                entry["line"] = item["line"]
        clean.append(entry)
    return {"verdict": answer["verdict"], "findings": clean}


def live_answer(config: dict[str, Any], reviewer: dict[str, str], api_key: str, delta: str) -> tuple[str, dict[str, Any]]:
    policy = POLICY_PATH.read_text(encoding="utf-8")
    body = {
        "model": reviewer["openrouter_id"],
        "messages": [{"role": "system", "content": policy}, {"role": "user", "content": delta}],
        "temperature": 0,
        "max_tokens": config["max_output_tokens"],
        "response_format": {"type": "json_object"},
        "usage": {"include": True},
    }
    response = openrouter_post(config, api_key, body)
    try:
        choice = response["choices"][0]
        content = choice["message"]["content"]
        finish = choice.get("finish_reason")
        served = response["model"]
    except (KeyError, IndexError, TypeError) as exc:
        raise PermitError("provider response has no completion") from exc
    if not isinstance(content, str) or not content.strip():
        raise PermitError("provider returned an empty completion")
    if finish != "stop":
        raise PermitError(f"completion did not finish cleanly (finish_reason={finish})")
    if not isinstance(served, str) or served.split("/", 1)[0] != reviewer["provider"]:
        raise PermitError(f"served model {served!r} is not from provider {reviewer['provider']}")
    return content, {"served_model": served, "usage": response.get("usage")}


def run_review(
    context_path: Path,
    outdir: Path,
    fixtures: Path | None,
    env: dict[str, str],
) -> None:
    context_bytes = context_path.read_bytes()
    context = json.loads(context_bytes)
    context_sha = sha256_hex(context_bytes)
    config = load_reviewers()
    wanted = [{"provider": r["provider"], "model": r["model"]} for r in config["reviewers"]]
    if context.get("required_reviewers") != wanted:
        raise PermitError("context quorum does not match release/permit-reviewers.json")
    api_key = ""
    if fixtures is None:
        api_key = env.get(config["secret_env"], "")
        if not api_key:
            raise PermitError(f"{config['secret_env']} is not set; the review quorum cannot run")
        delta = release_delta(context, config["max_prompt_bytes"])
    else:
        delta = ""
    outdir.mkdir(parents=True, exist_ok=True)

    for reviewer in config["reviewers"]:
        label = f"{reviewer['provider']}-{reviewer['model']}"
        if fixtures is not None:
            content = (fixtures / f"{reviewer['provider']}.json").read_text(encoding="utf-8")
            meta: dict[str, Any] = {"served_model": "fixture", "usage": None}
        else:
            content, meta = live_answer(config, reviewer, api_key, delta)
        answer = parse_answer(content)
        review = {
            "schema": REVIEW_SCHEMA,
            "repository": context["repository"],
            "pull_request": context["pull_request"],
            "base_sha": context["base_sha"],
            "head_sha": context["head_sha"],
            "merge_sha": context["merge_sha"],
            "merge_tree_sha": context["merge_tree_sha"],
            "workflow_sha": context["workflow_sha"],
            "run_id": context["run_id"],
            "run_attempt": context["run_attempt"],
            "context_sha256": context_sha,
            "reviewer": {"provider": reviewer["provider"], "model": reviewer["model"]},
            "verdict": answer["verdict"],
            "response_sha256": sha256_hex(content.encode("utf-8")),
            "findings": answer["findings"],
        }
        (outdir / f"review-{label}.json").write_text(json.dumps(review, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (outdir / f"response-{label}.txt").write_text(content, encoding="utf-8")
        (outdir / f"usage-{label}.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"review {label}: {answer['verdict']} ({len(answer['findings'])} findings)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    ctx = sub.add_parser("context", help="write the commit-bound release-permit context")
    ctx.add_argument("--output", required=True)
    ctx.add_argument("--commit", required=True, help="the full SHA of the commit to release")
    ctx.add_argument("--tag", help="the release tag under review (excluded from the previous-release search)")
    ctx.add_argument("--pull-request", type=int, help="override the merged-PR lookup (rehearsal only)")
    rev = sub.add_parser("review", help="collect both provider reviews")
    rev.add_argument("--context", required=True)
    rev.add_argument("--outdir", required=True)
    rev.add_argument("--fixtures", help="recorded model answers; no network, no spend (rehearsal only)")
    args = parser.parse_args(argv)
    try:
        if args.command == "context":
            context = build_context(
                env=dict(os.environ), commit=args.commit, tag=args.tag, fetch=github_fetch,
                pull_request=args.pull_request,
            )
            Path(args.output).write_bytes(encode_context(context))
            print(f"context for {context['head_sha']} (delta from {context['_previous_release']}, PR #{context['pull_request']})")
        else:
            run_review(Path(args.context), Path(args.outdir), Path(args.fixtures) if args.fixtures else None, dict(os.environ))
    except (PermitError, OSError, ValueError, KeyError) as exc:
        die(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
