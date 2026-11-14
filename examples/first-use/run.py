#!/usr/bin/env python3
"""Run the public HTTP decision/receipt journey with an isolated local server.

quantum_posture: verifies classical Ed25519 receipts using the standalone verifier;
this walkthrough makes no post-quantum protection claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[2]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def free_ports() -> tuple[int, int]:
    # Hold both sockets until both choices are made. If another process claims
    # one before serve binds it, startup fails; never attach to another server.
    with socket.socket() as api, socket.socket() as health:
        api.bind(("127.0.0.1", 0))
        health.bind(("127.0.0.1", 0))
        return api.getsockname()[1], health.getsockname()[1]


def run(args: argparse.Namespace, out: Path) -> None:
    kernel, verifier, policy = (path.resolve() for path in
                                (args.kernel, args.verifier, args.policy))
    for binary in (kernel, verifier):
        require(binary.is_file() and os.access(binary, os.X_OK),
                f"missing executable {binary}; run make build first")
    # Copy the public sample unchanged, including its relative reference pack.
    for source in (policy, policy.with_suffix(".json")):
        shutil.copyfile(source, out / source.name)
    home = out / "home"
    home.mkdir(mode=0o700)
    data = out / "data"
    api_port, health_port = free_ports()
    token = secrets.token_hex(32)
    # Do not inherit provider keys, DATABASE_URL, proxy settings or existing
    # HELM configuration from the caller's environment.
    env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(home),
           "HELM_ADMIN_API_KEY": token,
           "HELM_RUNTIME_TENANT_ID": "first-use",
           "HELM_RUNTIME_PRINCIPAL_ID": "first-use-principal",
           "HELM_RECEIPT_PROFILE": "classical",
           "HELM_HEALTH_PORT": str(health_port)}
    command = [str(kernel), "serve", "--policy", str(out / policy.name),
               "--data-dir", str(data), "--addr", "127.0.0.1", "--port", str(api_port)]
    manifest = {
        "scope": "local HTTP evaluation and offline receipt verification; no tool dispatch",
        "command": command,
        "environment": {key: value for key, value in env.items()
                        if key != "HELM_ADMIN_API_KEY"},
        "admin_credential": "random per-run credential; not retained",
        "sha256": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in (kernel, verifier, policy, policy.with_suffix(".json"))},
    }
    write_json(out / "run.json", manifest)
    base = f"http://127.0.0.1:{api_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    headers = {"Authorization": f"Bearer {token}",
               "X-Helm-Tenant-ID": "first-use",
               "X-Helm-Principal-ID": "first-use-principal",
               "Content-Type": "application/json"}

    def request(route: str, body: dict | None = None,
                auth: dict | None = None) -> tuple[int, bytes]:
        req = urllib.request.Request(base + route,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers=headers if auth is None else auth)
        try:
            with opener.open(req, timeout=5) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    with (out / "serve.log").open("w") as log:
        server = subprocess.Popen(command, cwd=out, env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while True:
                require(server.poll() is None, "server exited during startup; inspect serve.log")
                try:
                    status, _ = request("/healthz", auth={})
                    if status == 200:
                        break
                except (urllib.error.URLError, TimeoutError):
                    pass
                require(time.monotonic() < deadline, "server readiness timeout; inspect serve.log")
                time.sleep(0.05)

            allow = {"tool": "read-ticket", "effect_level": "ticket:FIRST-USE",
                     "session_id": "first-use", "args": {"example": "first-use"}}
            # A block-everything server cannot pass: these refusal cases share
            # the same benign request that must subsequently receive ALLOW.
            for label, auth, expected in (
                ("unauthenticated", {}, 401),
                ("wrong-tenant", {**headers, "X-Helm-Tenant-ID": "other-tenant"}, 403),
            ):
                status, body = request("/api/v1/evaluate", allow, auth)
                (out / f"{label}.json").write_bytes(body)
                require(status == expected, f"{label}: HTTP {status}, expected {expected}")
                print(f"{label}: HTTP {status}", flush=True)

            receipts = []
            for label, payload, expected in (
                ("allow", allow, "ALLOW"),
                ("deny", {**allow, "tool": "dangerous-shell", "effect_level": "system:shell"}, "DENY"),
            ):
                require(server.poll() is None, "server exited before evaluation")
                status, body = request("/api/v1/evaluate", payload)
                (out / f"{label}.decision.json").write_bytes(body)
                require(status == 200, f"{label}: evaluate returned HTTP {status}")
                decision = json.loads(body)
                require(decision.get("verdict") == expected, f"{label}: expected {expected}, got {decision}")
                receipt_id = decision.get("receipt_id")
                require(isinstance(receipt_id, str) and bool(receipt_id), f"{label}: missing receipt_id")
                status, body = request("/api/v1/receipts/" + urllib.parse.quote(receipt_id, safe=""))
                (out / f"{label}.receipt.json").write_bytes(body)
                require(status == 200, f"{label}: receipt fetch returned HTTP {status}")
                receipt = json.loads(body)
                require(receipt.get("receipt_id") == receipt_id, f"{label}: receipt id mismatch")
                require(receipt.get("decision_id") == decision.get("decision_id"),
                        f"{label}: decision id mismatch")
                require(receipt.get("verdict") == expected, f"{label}: receipt verdict mismatch")
                require(receipt.get("signature_version") == "receipt.v5", f"{label}: expected receipt.v5")
                require(receipt.get("effect_id") == payload["tool"], f"{label}: receipt effect mismatch")
                require(receipt.get("decision_hash") == decision.get("decision_hash"),
                        f"{label}: signed decision hash mismatch")
                receipts.append(receipt)
                print(f"{label}: {expected}; fetched corresponding receipt.v5", flush=True)
            shutil.copyfile(data / "root.pub", out / "root.pub")
        finally:
            if server.poll() is None:
                server.send_signal(signal.SIGINT)
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
            manifest["server_exit"] = server.returncode
            write_json(out / "run.json", manifest)
        require(server.returncode == 0, f"server shutdown exited {server.returncode}")

    # Every verifier invocation happens after the task-owned server has exited.
    print("server stopped; verifying exported receipts offline", flush=True)
    tampered = {**receipts[0], "verdict": "DENY"}
    write_json(out / "tampered.receipt.json", tampered)
    # A correctly sized unrelated Ed25519 public key, deliberately not root.pub.
    (out / "wrong.pub").write_text("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\n")
    checks = []
    for label, receipt, key, expected in (
        ("allow", "allow.receipt.json", "root.pub", 0),
        ("deny", "deny.receipt.json", "root.pub", 0),
        ("tampered", "tampered.receipt.json", "root.pub", 1),
        ("wrong-key", "allow.receipt.json", "wrong.pub", 1),
    ):
        verify = [str(verifier), "--receipt", str(out / receipt),
                  "--key-file", str(out / key), "--json"]
        result = subprocess.run(verify, env=env, capture_output=True, text=True, timeout=10)
        (out / f"{label}.verification.json").write_text(result.stdout)
        (out / f"{label}.verification.stderr").write_text(result.stderr)
        checks.append({"case": label, "command": verify, "exit": result.returncode,
                       "expected_exit": expected})
        write_json(out / "verification-commands.json", checks)
        require(result.returncode == expected,
                f"{label}: receipt_verify exited {result.returncode}, expected {expected}")
        print(f"{label}: receipt_verify exit {result.returncode} (expected {expected})", flush=True)
    write_json(out / "result.json", {"result": "PASS", "checks": checks,
                                    "scope": manifest["scope"]})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="new directory for evidence (default: temporary directory)")
    parser.add_argument("--kernel", type=Path, default=ROOT / "bin/helm-ai-kernel")
    parser.add_argument("--verifier", type=Path, default=ROOT / "bin/receipt_verify")
    parser.add_argument("--policy", type=Path,
                        default=ROOT / "examples/launch/policies/agent_tool_call_boundary.toml")
    args = parser.parse_args()
    if args.out:
        out = args.out.resolve()
        out.mkdir(mode=0o700, parents=True, exist_ok=False)
    else:
        out = Path(tempfile.mkdtemp(prefix="helm-first-use-"))
    print(f"Evidence: {out}", flush=True)
    try:
        run(args, out)
    except Exception as exc:
        write_json(out / "result.json", {"result": "FAIL", "error": str(exc)})
        print(f"FAIL: {exc}; evidence: {out}", file=sys.stderr)
        return 1
    print("PASS: local authenticated ALLOW/DENY and offline receipt checks", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
