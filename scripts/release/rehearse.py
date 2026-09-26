#!/usr/bin/env python3
"""Rehearse the next Kernel release against main before anyone tags it.

The v0.9.0 release hit five blockers only after its tag was pushed, each of
which was checkable in advance. This script works out the version the next tag
would carry and checks every pre-publish precondition of
.github/workflows/release.yml that can be read from a checkout, the public
registries, or the workflow context, then prints one Markdown table.

Statuses:
  PASS           the precondition was checked and holds.
  FAIL           a defect that blocks the release whatever version is chosen.
  ACTION-NEEDED  a per-release step with a known remedy (bump, sync, pin, tag).
  UNKNOWN        the precondition could not be read here; it is never a PASS.

Exit codes: 1 when any check FAILs (or, with --strict, is ACTION-NEEDED);
0 otherwise. UNKNOWN never changes the exit code.

quantum_posture: release rehearsal compares version strings, git blob SHA-1
identities and rendered manifests; it implements no cryptographic control.
"""
from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_version_drift as drift  # noqa: E402
import console_local_sidecar as sidecar  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "Mindburn-Labs/helm-ai-kernel"
KERNEL_SPEC = "api/openapi/helm.openapi.yaml"
CATALOG_URL = (
    "https://api.github.com/repos/Mindburn-Labs/contracts-catalog/contents/"
    "api/specs/helm.openapi.yaml?ref=main"
)
ENVIRONMENTS_URL = f"https://api.github.com/repos/{REPOSITORY}/environments"
CONSOLE_REMOTE = "https://github.com/Mindburn-Labs/app-helm-console.git"
PINS = "release/console-local-sidecar-pins.json"
SEMVER_TAG = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)$")
TIMEOUT = 20

PASS, FAIL, ACTION, UNKNOWN = "PASS", "FAIL", "ACTION-NEEDED", "UNKNOWN"

# The Kernel refuses to start with one half of these pairs (#1062 fixed the
# chart wiring the organization-runtime key without the activation key).
CHART_ENV_PAIRS = (
    ("HELM_ORGANIZATION_RUNTIME_API_KEY", "HELM_CONTROL_PLANE_ACTIVATION_PUBLIC_KEY"),
    ("HELM_TLS_CERT_FILE", "HELM_TLS_KEY_FILE"),
)
RENDER_ONLY_HEX = "0123456789abcdef" * 4
# The release smoke's production controlplane render (scripts/ci/helm_chart_smoke.sh),
# with every credential moved to an existing Secret the way a real production
# install supplies it, and native TLS on. The smoke passes its API keys inline,
# which never wires the organization-runtime key; that is how #5 shipped.
CHART_PRODUCTION_ARGS = (
    "--values", "scripts/ci/helm_production_network_policy_values.yaml",
    "--set", f"image.digest=sha256:{RENDER_ONLY_HEX}",
    "--set", "image.repository=ghcr.io/mindburn-labs/helm-ai-kernel",
    "--set", "helm.production=true",
    "--set", "helm.policy.source.kind=controlplane",
    "--set", "helm.policy.source.controlplane.url=https://helm-controlplane.example.internal",
    "--set", "helm.policy.source.controlplane.tls.existingSecret=helm-policy-controlplane-ca",
    "--set", "helm.policy.signature.required=true",
    "--set", f"helm.policy.signature.publicKey={RENDER_ONLY_HEX}",
    "--set", "helm.signing.existingSecret=helm-kernel-signing",
    "--set", "helm.auth.existingSecret=helm-kernel-auth",
    "--set", "helm.tls.existingSecret=helm-kernel-tls",
)

# Trusted-publisher settings are private to each registry account, so the
# rehearsal can only state what must be configured there.
TRUSTED_PUBLISHERS = {
    "npm-sdk": ("npm", "npm package {name}: Settings > Trusted publishing > GitHub Actions"),
    "python-sdk": ("PyPI", "PyPI project {name}: Manage > Publishing > GitHub (a pending publisher if the project is new)"),
    "crates-sdk": ("crates.io", "crate {name}: Settings > Trusted Publishing > GitHub"),
}


@dataclass
class Check:
    name: str
    status: str
    detail: str
    remedy: str = ""


@dataclass
class Plan:
    """The version the next tag would carry, and how it was chosen."""

    latest_tag: str
    version: str
    would_be: str
    mode: str  # "version" (VERSION is ahead), "computed", or "nothing"
    required_bump: str
    commits_since: int
    checks: list[Check] = field(default_factory=list)


def run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=False)


def parse_semver(value: str) -> tuple[int, int, int] | None:
    match = SEMVER_TAG.match(value if value.startswith("v") else f"v{value}")
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def bump(version: str, kind: str) -> str:
    major, minor, patch = parse_semver(version) or (0, 0, 0)
    if kind == "major":
        return f"{major + 1}.0.0"
    if kind == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def break_allowed(current: str, base: str, root: Path = ROOT) -> bool:
    """Apply contract_breaking.sh's own break_allowed rule, not a copy of it."""
    script = (root / "scripts/ci/contract_breaking.sh").read_text(encoding="utf-8")
    functions = re.search(r"^major\(\) \{.*?$", script, re.MULTILINE)
    rule = re.search(r"^break_allowed\(\) \{\n.*?^\}$", script, re.MULTILINE | re.DOTALL)
    if not functions or not rule:
        raise RuntimeError("scripts/ci/contract_breaking.sh no longer defines major() and break_allowed()")
    body = f"{functions[0]}\n{rule[0]}\nbreak_allowed \"$1\" \"$2\"\n"
    return run(["bash", "-c", body, "break_allowed", current, base], cwd=root).returncode == 0


def minimal_bump(base: str, broke: bool, root: Path = ROOT) -> str:
    if not broke:
        return "patch"
    for kind in ("patch", "minor", "major"):
        if break_allowed(bump(base, kind), base, root):
            return kind
    raise RuntimeError(f"no version bump from {base} permits a contract break")


def latest_tag(root: Path) -> str | None:
    tags = run(["git", "tag", "--list", "v*"], cwd=root).stdout.split()
    versions = [(parse_semver(tag), tag) for tag in tags if parse_semver(tag)]
    return max(versions)[1] if versions else None


def contract_gate(kind: str, root: Path) -> tuple[int, str]:
    result = run(["bash", "scripts/ci/contract_breaking.sh", kind, "release"], cwd=root)
    return result.returncode, (result.stdout + result.stderr).strip()


def first_error(output: str) -> str:
    for line in output.splitlines():
        if line.startswith("::error::"):
            return line.removeprefix("::error::")
    return output.splitlines()[-1] if output else "no output"


def plan_version(root: Path = ROOT) -> Plan:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    tag = latest_tag(root)
    if tag is None or parse_semver(version) is None:
        raise RuntimeError(f"need a semver VERSION ({version!r}) and at least one vX.Y.Z tag ({tag!r})")
    tag_version = tag[1:]
    count = run(["git", "rev-list", "--count", f"{tag}..HEAD"], cwd=root).stdout.strip()
    commits_since = int(count) if count.isdigit() else 0

    if parse_semver(version) > parse_semver(tag_version):
        mode = "version"
    elif commits_since == 0:
        mode = "nothing"
    else:
        mode = "computed"

    gates = {kind: contract_gate(kind, root) for kind in ("openapi", "proto")}
    broke = any(code == 1 for code, _ in gates.values())
    unknown = any(code not in (0, 1) for code, _ in gates.values())
    needed = minimal_bump(tag_version, broke, root)
    if mode == "computed":
        would_be = bump(tag_version, needed)
        required = needed if broke or not unknown else "patch (lower bound: a contract gate could not run)"
    else:
        would_be = version
        required = needed if broke else "none beyond VERSION" if mode == "version" else "none"

    plan = Plan(tag, version, would_be, mode, required, commits_since)
    for kind, (code, output) in gates.items():
        name = f"(a) contract gate: {kind} (release mode)"
        if code == 0:
            plan.checks.append(Check(name, PASS, output.splitlines()[-1] if output else "pass"))
        elif code == 1 and break_allowed(would_be, tag_version, root):
            plan.checks.append(Check(name, PASS, f"breaking change since {tag}; {would_be} is a {needed} bump, which permits it"))
        elif code == 1:
            target = bump(tag_version, needed)
            plan.checks.append(Check(
                name, ACTION, f"breaking change since {tag} needs a {needed} bump; VERSION is {version}",
                f"make prepare-version VERSION={target}",
            ))
        else:
            plan.checks.append(Check(
                name, UNKNOWN, f"gate did not run (exit {code}): {first_error(output)}",
                "install oasdiff and buf (scripts/ci/install_check_tools.sh), then re-run",
            ))
    return plan


# ---------------------------------------------------------------- fetching

def http_get(url: str, token: str | None = None) -> tuple[int, bytes]:
    """Return (status, body). Raises OSError for transport failures."""
    headers = drift.http_headers(url)
    if token and urllib.parse.urlsplit(url).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


Fetch = Callable[..., "tuple[int, bytes]"]


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def spec_at_version(root: Path, version: str) -> bytes:
    """The Kernel spec bytes the tag would carry: prepare_version.py's own rewrite."""
    text = (root / KERNEL_SPEC).read_text(encoding="utf-8")
    contract = drift.load_contract(root / "release/version-surfaces.yaml")
    for surface in contract.get("local_surfaces", []):
        if surface.get("path") == KERNEL_SPEC and surface.get("kind") == "regex" and "replacement" in surface:
            text = re.sub(
                surface["pattern"], drift.fmt(surface["replacement"], version), text,
                count=int(surface.get("max_replacements", 0)), flags=re.MULTILINE,
            )
    return text.encode("utf-8")


def spec_summary(old: str, new: str) -> str:
    diff = list(difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0))
    added = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))
    path_re = re.compile(r"^[+-]  (/\S*):\s*$")
    paths = [f"{line[0]}{path_re.match(line)[1]}" for line in diff if path_re.match(line)]
    version_re = re.compile(r"^  version:\s*[\"']?([^\"'\s]+)", re.MULTILINE)
    old_v, new_v = version_re.search(old), version_re.search(new)
    parts = [f"tag spec +{added}/-{removed} lines vs catalog"]
    if old_v and new_v and old_v[1] != new_v[1]:
        parts.append(f"info.version {old_v[1]} -> {new_v[1]}")
    if paths:
        parts.append("paths " + ", ".join(paths[:6]) + (" ..." if len(paths) > 6 else ""))
    return "; ".join(parts)


def check_catalog(root: Path, would_be: str, fetch: Fetch = http_get, token: str | None = None) -> Check:
    name = "(b) contracts-catalog spec = tag spec"
    expected = spec_at_version(root, would_be)
    expected_sha = git_blob_sha(expected)
    try:
        status, body = fetch(CATALOG_URL, token)
    except OSError as exc:
        return Check(name, UNKNOWN, f"catalog fetch failed: {exc}", "re-run; the release preflight reads it with DOWNSTREAM_FANOUT_TOKEN")
    if status != 200:
        reason = {404: "not found or not readable without a token", 403: "forbidden or rate limited", 429: "rate limited"}
        return Check(
            name, UNKNOWN, f"catalog read returned HTTP {status} ({reason.get(status, 'unexpected')})",
            "run with GITHUB_TOKEN or DOWNSTREAM_FANOUT_TOKEN able to read Mindburn-Labs/contracts-catalog",
        )
    try:
        payload = json.loads(body)
        catalog_sha = payload["sha"]
    except (ValueError, KeyError, TypeError):
        return Check(name, UNKNOWN, "catalog response carried no blob sha")
    if catalog_sha == expected_sha:
        return Check(name, PASS, f"catalog main blob {catalog_sha[:12]} = v{would_be} spec")
    try:
        catalog_text = base64.b64decode(payload.get("content") or "").decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        catalog_text = ""
    summary = spec_summary(catalog_text, expected.decode("utf-8")) if catalog_text else "catalog content not returned"
    return Check(
        name, ACTION, f"catalog blob {catalog_sha[:12]} != v{would_be} spec blob {expected_sha[:12]}: {summary}",
        f"sync PR needed before tagging: copy {KERNEL_SPEC} (at v{would_be}) to contracts-catalog api/specs/helm.openapi.yaml and merge",
    )


def check_console_pin(root: Path, would_be: str, ls_remote: Callable[[str], subprocess.CompletedProcess[str]] | None = None) -> list[Check]:
    tag = f"v{would_be}"
    row = "(c) console sidecar pin row"
    pin: dict | None = None
    try:
        pin = sidecar.resolve_pin(root / PINS, tag)
        checks = [Check(row, PASS, f"{tag} -> {pin['source']['commit'][:12]} ({pin['workflow_ref']})")]
    except ValueError as exc:
        if "found 0" not in str(exc):
            return [Check(row, FAIL, str(exc), f"repair {PINS}")]
        checks = [Check(
            row, ACTION, f"{PINS} has no row for {tag}",
            f"add a {tag} row naming the reviewed app-helm-console commit, tree, version and package-lock sha256",
        )]

    # Without a row, still report the conventional tag the row would name.
    ref = pin["workflow_ref"] if pin else f"refs/tags/helm-console-sidecar-{tag}"
    commit = pin["source"]["commit"] if pin else None
    name = f"(c) console tag {ref.removeprefix('refs/tags/')}"
    ls_remote = ls_remote or (lambda r: run(
        ["git", "ls-remote", CONSOLE_REMOTE, r, f"{r}^{{}}"], cwd=root,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}, timeout=60,
    ))
    result = ls_remote(ref)
    if result.returncode != 0:
        return checks + [Check(name, UNKNOWN, f"git ls-remote failed: {result.stderr.strip()[:200]}")]
    refs: dict[str, str] = {}
    for line in result.stdout.splitlines():
        sha, _, refname = line.partition("\t")
        refs[refname] = sha
    create = f"in app-helm-console: git tag -a {ref.removeprefix('refs/tags/')} {commit or '<reviewed commit>'} -m '...' and push it"
    if ref not in refs:
        return checks + [Check(name, ACTION, "tag does not exist", create)]
    peeled = refs.get(f"{ref}^{{}}")
    if peeled is None:
        return checks + [Check(name, ACTION, "tag is lightweight; the release needs an annotated tag", create)]
    if commit is None:
        return checks + [Check(name, PASS, f"annotated, peels to {peeled[:12]}; the pin row must name that commit")]
    if peeled != commit:
        return checks + [Check(name, ACTION, f"tag peels to {peeled[:12]}, pin names {commit[:12]}", "pin the commit the tag names, or tag the pinned commit under a new name")]
    return checks + [Check(name, PASS, f"annotated, peels to pinned commit {peeled[:12]}")]


def check_version_drift(root: Path, plan: Plan) -> Check:
    name = "(d) version-drift local"
    script = ["python3", "scripts/release/check_version_drift.py"]
    lockstep = run(script + ["local"], cwd=root)
    if lockstep.returncode != 0:
        drifted = [line for line in lockstep.stdout.splitlines() if line.startswith("FAIL")]
        return Check(name, FAIL, f"source surfaces disagree with VERSION {plan.version}: {'; '.join(drifted[:3]) or 'see make version-drift'}", "make prepare-version VERSION=<version>")
    if plan.would_be != plan.version:
        return Check(name, ACTION, f"surfaces are in lockstep at {plan.version}; the tag would be v{plan.would_be}", f"make prepare-version VERSION={plan.would_be}")
    tagged = run(script + ["local", "--tag", f"v{plan.would_be}"], cwd=root)
    if tagged.returncode != 0:
        return Check(name, FAIL, f"check_version_drift.py local --tag v{plan.would_be} failed", "make version-drift")
    return Check(name, PASS, f"all source surfaces = {plan.would_be}; tag v{plan.would_be} accepted")


# ---------------------------------------------------------------- release.yml

def workflow_jobs(workflow: str) -> dict[str, str]:
    return {
        match["name"]: match["body"]
        for match in re.finditer(
            r"^  (?P<name>[A-Za-z0-9_-]+):\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            workflow.split("\njobs:\n", 1)[1], re.MULTILINE | re.DOTALL,
        )
    }


def job_environment(body: str) -> str | None:
    match = re.search(r"^    environment: (\S+)$", body, re.MULTILINE)
    return match[1] if match else None


def release_inputs(workflow: str) -> tuple[dict[str, set[str]], set[str]]:
    """Secrets named in release.yml (name -> environments of the jobs reading it) and vars."""
    secrets: dict[str, set[str]] = {}
    variables: set[str] = set()
    for body in workflow_jobs(workflow).values():
        environment = job_environment(body) or ""
        for name in re.findall(r"secrets\.([A-Z0-9_]+)", body):
            if name != "GITHUB_TOKEN":
                secrets.setdefault(name, set()).add(environment)
        variables.update(re.findall(r"vars\.([A-Z0-9_]+)", body))
    return secrets, variables


def check_registries(root: Path, workflow: str, would_be: str, fetch: Fetch = http_get) -> list[Check]:
    jobs = workflow_jobs(workflow)
    npm_name = json.loads((root / "sdk/ts/package.json").read_text(encoding="utf-8"))["name"]
    lookups = {
        "npm-sdk": (npm_name, f"https://registry.npmjs.org/{urllib.parse.quote(npm_name, safe='@')}", lambda d: would_be in d.get("versions", {})),
        "python-sdk": ("helm-sdk", "https://pypi.org/pypi/helm-sdk/json", lambda d: would_be in d.get("releases", {})),
        "crates-sdk": ("helm-sdk", "https://crates.io/api/v1/crates/helm-sdk", lambda d: any(v.get("num") == would_be for v in d.get("versions", []))),
    }
    checks: list[Check] = []
    for job, (package, url, has_version) in lookups.items():
        registry, where = TRUSTED_PUBLISHERS[job]
        name = f"(e) {registry} {package}"
        try:
            status, body = fetch(url)
        except OSError as exc:
            checks.append(Check(name, UNKNOWN, f"registry read failed: {exc}"))
            status = None
        if status == 200:
            try:
                published = has_version(json.loads(body))
            except (ValueError, AttributeError):
                published = False
            note = f"; {would_be} already published, the job will skip it" if published else ""
            checks.append(Check(name, PASS, f"exists{note}"))
        elif status == 404:
            first = "PyPI accepts a pending trusted publisher for a new project" if job == "python-sdk" else f"{registry} configures trusted publishing on an existing package, so publish it once first"
            checks.append(Check(name, ACTION, "not found on the registry", first))
        elif status is not None:
            checks.append(Check(name, UNKNOWN, f"registry returned HTTP {status}"))

        body = jobs.get(job, "")
        environment = job_environment(body)
        if "id-token: write" not in body or environment is None:
            checks.append(Check(f"(e) {registry} OIDC publish job", FAIL, f"release.yml {job} lacks id-token: write or an environment", "restore the trusted-publishing job shape"))
            continue
        checks.append(Check(
            f"(e) {registry} trusted publisher", UNKNOWN,
            "registry publisher settings are not readable anonymously",
            f"{where.format(name=package)}: owner Mindburn-Labs, repository helm-ai-kernel, workflow release.yml, environment {environment}",
        ))
    return checks


def check_environments(workflow: str, fetch: Fetch = http_get) -> Check:
    name = "(g) GitHub deployment environments"
    wanted = sorted({env for env in map(job_environment, workflow_jobs(workflow).values()) if env})
    try:
        status, body = fetch(ENVIRONMENTS_URL)
    except OSError as exc:
        return Check(name, UNKNOWN, f"environments read failed: {exc}")
    if status != 200:
        return Check(name, UNKNOWN, f"environments read returned HTTP {status}")
    present = {env.get("name") for env in json.loads(body).get("environments", [])}
    missing = [env for env in wanted if env not in present]
    if missing:
        return Check(name, FAIL, f"missing {', '.join(missing)}", "create them under Settings > Environments")
    return Check(name, PASS, f"{', '.join(wanted)} exist")


def check_secrets(workflow: str, env: dict[str, str]) -> list[Check]:
    """Presence of release.yml's secrets and variables, as the rehearsal workflow reports it.

    The rehearsal workflow passes REHEARSAL_HAS_<NAME>=true|false computed by
    `secrets.<NAME> != ''`, so no secret value enters the job. A name the
    workflow does not report stays UNKNOWN, never PASS.
    """
    secrets, variables = release_inputs(workflow)
    checks: list[Check] = []
    scoped: dict[str, list[str]] = {}
    for name in sorted(secrets):
        if "" not in secrets[name]:
            for environment in secrets[name]:
                scoped.setdefault(environment, []).append(name)
            continue
        checks.append(_presence(f"(g) secret {name}", env.get(f"REHEARSAL_HAS_{name}"), f"add repository secret {name}"))
    for environment, names in sorted(scoped.items()):
        checks.append(Check(
            f"(g) {environment} environment secrets", UNKNOWN,
            f"{', '.join(names)} are visible only to a job that declares {environment}",
            f"verify under Settings > Environments > {environment}",
        ))
    for name in sorted(variables):
        checks.append(_presence(f"(g) variable {name}", env.get(f"REHEARSAL_HAS_{name}"), f"add repository variable {name}"))
    return checks


def _presence(label: str, reported: str | None, remedy: str) -> Check:
    if reported == "true":
        return Check(label, PASS, "configured (presence only; the value is not validated)")
    if reported == "false":
        return Check(label, FAIL, "not configured; release.yml fails without it", remedy)
    return Check(label, UNKNOWN, "not visible in this context (a local run, or not wired into release-rehearsal.yml)")


def check_on_main(root: Path) -> Check:
    name = "(g) HEAD reachable from origin/main"
    if run(["git", "rev-parse", "--verify", "--quiet", "origin/main^{commit}"], cwd=root).returncode != 0:
        return Check(name, UNKNOWN, "origin/main is not fetched here")
    if run(["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"], cwd=root).returncode == 0:
        return Check(name, PASS, "the release preflight accepts a tag on this commit")
    return Check(name, ACTION, "HEAD is not on origin/main", "tag a commit that is on main")


def helm_command() -> list[str] | None:
    candidates = [os.environ.get("KUBE_HELM_CMD"), "kube-helm", "helm"]
    for candidate in filter(None, candidates):
        path = shutil.which(candidate)
        if not path:
            continue
        # `helm` may be the HELM Kernel CLI; only Kubernetes Helm prints v3/v4.
        probe = subprocess.run([path, "version", "--short"], capture_output=True, text=True, check=False)
        if re.match(r"^v[34]\.", probe.stdout.strip()):
            return [path]
    return None


def env_names(rendered: str) -> set[str]:
    names: set[str] = set()
    for document in re.split(r"^---\s*$", rendered, flags=re.MULTILINE):
        if re.search(r"^kind: Deployment$", document, re.MULTILINE):
            names.update(re.findall(r"^\s*- name: (HELM_[A-Z0-9_]+)\s*$", document, re.MULTILINE))
    return names


def check_chart_pairs(rendered: str) -> Check:
    name = "(f) chart key pairs"
    names = env_names(rendered)
    broken = [f"{a} without {b}" if a in names else f"{b} without {a}" for a, b in CHART_ENV_PAIRS if (a in names) != (b in names)]
    if broken:
        return Check(name, FAIL, "; ".join(broken) + " (the Kernel refuses to start)", "wire both halves of each pair together in deploy/helm-chart/templates/deployment.yaml")
    if "HELM_TLS_CERT_FILE" not in names:
        return Check(name, FAIL, "helm.tls.existingSecret was set but TLS is not wired, so the pair check proved nothing", "check the chart's TLS wiring")
    wired = [f"{a}+{b}" for a, b in CHART_ENV_PAIRS if a in names]
    return Check(name, PASS, f"consistent; wired: {', '.join(wired)}")


def check_chart(root: Path) -> list[Check]:
    helm = helm_command()
    if helm is None:
        return [Check("(f) chart render", UNKNOWN, "Kubernetes Helm not found (KUBE_HELM_CMD, kube-helm, helm)", "install Helm v3 or set KUBE_HELM_CMD")]
    chart = "deploy/helm-chart"
    lint = run(helm + ["lint", chart, *CHART_PRODUCTION_ARGS], cwd=root)
    template = run(helm + ["template", "helm-ai-kernel", chart, "--namespace", "helm-ai-kernel", *CHART_PRODUCTION_ARGS], cwd=root)
    checks = [
        Check("(f) helm lint (production values)", PASS if lint.returncode == 0 else FAIL,
              "lint clean" if lint.returncode == 0 else first_error(lint.stdout + lint.stderr)[:300]),
    ]
    if template.returncode != 0:
        return checks + [Check("(f) chart render (production values)", FAIL, first_error(template.stderr)[:300], "make helm-chart-smoke")]
    return checks + [Check("(f) chart render (production values)", PASS, "renders"), check_chart_pairs(template.stdout)]


def not_rehearsed() -> list[Check]:
    return [
        Check("(g) release tag form", UNKNOWN, "checked only when the tag exists: annotated, on origin/main, equal to v$(VERSION)",
              "git tag -a v<version> -m 'Release v<version>' <commit on main> && git push origin v<version>"),
        Check("(g) validate: make quality-release", UNKNOWN, "not rehearsed here (docker, crucible, reproducible builds, SBOM/VEX)",
              "make quality-release"),
    ]


# ---------------------------------------------------------------- report

def rehearse(root: Path = ROOT, env: dict[str, str] | None = None) -> Plan:
    env = dict(os.environ if env is None else env)
    plan = plan_version(root)
    workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
    token = env.get("DOWNSTREAM_FANOUT_TOKEN") or None
    catalog = check_catalog(root, plan.would_be, token=token or env.get("GITHUB_TOKEN") or None)
    plan.checks.append(catalog)
    plan.checks += check_console_pin(root, plan.would_be)
    plan.checks.append(check_version_drift(root, plan))
    plan.checks += check_registries(root, workflow, plan.would_be)
    plan.checks += check_chart(root)
    plan.checks.append(check_on_main(root))
    plan.checks.append(check_environments(workflow))
    secret_checks = check_secrets(workflow, env)
    if token:
        # The catalog read used the release preflight's own token, so its
        # outcome is a direct test of that secret, not just of its presence.
        if catalog.status in (PASS, ACTION):
            verdict = Check("(g) secret DOWNSTREAM_FANOUT_TOKEN", PASS, "configured and reads contracts-catalog")
        elif re.search(r"HTTP 40[134]", catalog.detail):
            verdict = Check("(g) secret DOWNSTREAM_FANOUT_TOKEN", FAIL, "configured but cannot read contracts-catalog",
                            "grant it contents:read on Mindburn-Labs/contracts-catalog")
        else:
            verdict = None
        if verdict:
            secret_checks = [verdict if c.name == verdict.name else c for c in secret_checks]
    plan.checks += secret_checks
    plan.checks += not_rehearsed()
    return plan


def exit_code(checks: list[Check], strict: bool = False) -> int:
    blocking = {FAIL, ACTION} if strict else {FAIL}
    return 1 if any(check.status in blocking for check in checks) else 0


def cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render(plan: Plan) -> str:
    headline = {
        "nothing": f"Nothing to release: HEAD is {plan.latest_tag}. Re-checking v{plan.would_be}.",
        "version": f"VERSION {plan.version} is ahead of {plan.latest_tag}: rehearsing v{plan.would_be}.",
        "computed": f"VERSION {plan.version} is already tagged; {plan.commits_since} commit(s) since {plan.latest_tag}: rehearsing v{plan.would_be}.",
    }[plan.mode]
    counts = {status: sum(1 for c in plan.checks if c.status == status) for status in (PASS, FAIL, ACTION, UNKNOWN)}
    lines = [
        "## Release rehearsal",
        "",
        headline,
        "",
        f"- Latest tag: `{plan.latest_tag}`; VERSION: `{plan.version}`; would-be tag: `v{plan.would_be}`",
        f"- Required bump: {plan.required_bump}",
        f"- {counts[PASS]} PASS, {counts[FAIL]} FAIL, {counts[ACTION]} ACTION-NEEDED, {counts[UNKNOWN]} UNKNOWN",
        "",
        "| Check | Status | Detail | Remedy |",
        "| --- | --- | --- | --- |",
    ]
    lines += [f"| {cell(c.name)} | {c.status} | {cell(c.detail)} | {cell(c.remedy)} |" for c in plan.checks]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--strict", action="store_true", help="exit non-zero on ACTION-NEEDED too")
    args = parser.parse_args(argv)
    plan = rehearse()
    sys.stdout.write(render(plan))
    return exit_code(plan.checks, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
