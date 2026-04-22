---
title: Conformance
---

# Conformance

HELM keeps a retained conformance profile under `tests/conformance/profile-v1/`. The profile describes the minimum checks an implementation must pass to match the public OSS kernel behavior documented in this repository.

## Run the Kernel Conformance Command

```bash
./bin/helm conform --level L1 --json
./bin/helm conform --level L2 --json
```

## Run the Conformance Test Suite

```bash
cd tests/conformance
go test ./...
```

## Profile Material

The profile directory contains:

- `checklist.yaml` for the machine-readable checklist
- `profile_test.go` for profile assertions
- `README.md` for the human-readable profile summary

## What L1 and L2 Mean in This Repo

- `L1` covers core structural correctness such as canonicalization, schema handling, and receipt shape.
- `L2` adds broader runtime verification around exported evidence, replay, and retained kernel invariants.

The exact checks are defined by the code and checklist in `tests/conformance/`, not by this page.
