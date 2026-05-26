# ADR 0001: Transition to Standalone Public Core Repository

## Context
Mindburn Labs is transitioning from a single-root local workspace layout to a highly decoupled 2026-2027 Polyrepo and Platform Engineering architecture to limit blast radius and isolate boundary enforcement services.

## Decision
We retain `helm-ai-kernel` permanently as the public open-source kernel and core execution firewall daemon repository. We decouple all commercial control plane modules, telemetry aggregators, and packaging shells into separate specialized microservice repositories.

## Consequences
* Instantly clear code boundaries for the open-source community.
* REST, Protobuf, and JSON interface schemas must be published dynamically to contract catalog repositories.
* Independent release cycles and OIDC-driven promotion pipelines.
