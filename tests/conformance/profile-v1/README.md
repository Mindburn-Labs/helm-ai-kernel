# HELM Conformance Profile v1

This directory defines the retained v1 conformance profile for the OSS kernel.

## Contents

- `checklist.yaml` contains the machine-readable checklist
- `profile_test.go` validates the profile wiring

## Intent

The profile captures the minimum checks a compatible implementation should pass for the public OSS kernel surface represented by this repository.

Future profile revisions should be introduced as additive new profile material rather than by rewriting this directory in place without versioning.
