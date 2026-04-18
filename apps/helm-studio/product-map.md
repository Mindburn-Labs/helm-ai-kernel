# HELM Studio - Stage 5 Screen-by-Screen Product Map

> **Status**: Ratified · **Version**: 1.0 · **Date**: 2026-03-22 · **Authors**: HELM Core

## Product thesis

HELM Studio is the unified control environment for an executable organization.

It is not a dashboard, a chatbot, a workflow builder, or an org chart tool.
It is the operational surface where a company is:

* designed,
* compiled,
* governed,
* deployed,
* supervised,
* mutated,
* and proven
  across humans, software, AI agents, and physical assets.

The primary experience is built around two core surfaces:

* **Mama AI Chat** - conversational command, synthesis, orchestration, and explanation
* **Canvas** - the visual, spatial, executable organization surface

Everything else in the product exists to support those two surfaces.

---

## Experience principles

### 1. Chat and canvas are primary

The user should be able to run the company from:

* chat,
* canvas,
* or a hybrid of both.

The product must never feel like:

* chat on one side,
* random admin pages on the other.

It must feel like a single executable system.

### 2. No parallel truth

UI state is never canonical by itself.
Every surface resolves to canonical system objects:

* OrgGenome
* principal / role / authority objects
* policy bundles
* deployment plans
* enterprise transactions
* phenotype snapshots
* evidence / replay artifacts

### 3. Org chart evolves into org operating graph

The canvas starts with an org-chart mental model but expands into:

* authority topology,
* workflow topology,
* systems topology,
* site/fleet topology,
* execution topology.

### 4. 2030-grade interaction model

The UI should feel:

* cinematic but precise,
* alive but not noisy,
* premium but not decorative,
* spatial but still rigorous,
* highly automated but always inspectable.

### 5. Full automation without loss of control

Mama AI should be able to:

* synthesize structures,
* compile mutations,
* route work,
* surface risks,
* run ops,
* coordinate humans and agents,
* prepare approvals,
* manage deployments,
* orchestrate physical assets,
  without turning the UI into a black box.

---

# Product shell

## Global shell layout

### Top bar

Persistent global controls:

* Workspace / Company selector
* Environment selector: Teams / Enterprise / Site / Global
* Time mode: Live / Replay / Snapshot / Simulation
* Search / command palette
* Notifications / escalations
* Safety / system status indicator
* Mama AI session status
* User / role / session authority badge

### Left rail

Primary navigation:

* Studio
* Inbox
* Operations
* Deployments
* Conformance
* Evidence
* Admin

### Center

Active screen / canvas / console

### Right rail

Persistent inspector / details / allowed actions / evidence / authority context

### Bottom rail

Optional live stream / execution feed / voice controls / timeline scrubber

---

# Primary navigation map

## 1. Studio

The organizational design and control environment.

Subsections:

* Canvas
* Genome
* Authority
* Policies
* Budgets
* Jurisdictions
* Mutations
* Simulation

## 2. Inbox

The arbitration and escalation layer.

Subsections:

* Approvals
* HOTL Escalations
* High-Risk Actions
* Deploy Gates
* Incident Decisions
* Mutation Reviews

## 3. Operations

The live operating surface.

Subsections:

* Mission Control
* Workflows
* Teams
* Sites
* Fleets
* Assets
* Incidents

## 4. Deployments

Everything related to rollout.

Subsections:

* Activation Plans
* Rollout Waves
* Fleet Versions
* Environment States
* Rollback

## 5. Conformance

The truth-checking and divergence layer.

Subsections:

* Phenotype
* Drift
* Policy Conformance
* Authority Conformance
* Site Conformance
* Budget Conformance

## 6. Evidence

Replay and proof.

Subsections:

* Replay
* Timelines
* EvidencePacks
* Transaction Proof
* Incident Proof
* Export Center

## 7. Admin

System administration.

Subsections:

* Principals
* Identity / Trust
* Connectors
* Integrations
* Sovereignty
* Safety Profiles
* Audit Settings

---

# Core interaction model

## Mode 1 - Chat-first

User enters through Mama AI and says:

* "Build me the operating structure for a cross-border AI-native consulting company in EU + UAE."
* "Show me why the Berlin site is in degraded conformance."
* "Prepare a mutation that narrows finance authority in EMEA."
* "Create a safe rollout plan for warehouse fleet version 12.3."

Mama AI responds by:

* generating canonical objects,
* previewing visual changes in canvas,
* opening inspectors,
* assembling approvals,
* showing compile previews,
* surfacing risks.

## Mode 2 - Canvas-first

User drags, edits, expands, connects, opens subgraphs, and manipulates organization visually.
Mama AI remains present as co-pilot and can:

* explain,
* auto-complete,
* propose,
* validate,
* compile,
* simulate,
* activate.

## Mode 3 - Hybrid

The default best mode.
User and Mama AI co-create changes across visual, structured, and conversational surfaces.

---

# Screen-by-screen map

# A. HELM Studio

## Screen A1 - HELM Studio Home

### Purpose

Landing environment for controlling the company.

### Main content

* Live company state summary
* Active mutations / approvals / incidents
* Current environment health
* Top 5 critical drift or safety signals
* Quick-launch cards:

  * Open Canvas
  * Ask Mama AI
  * Review Inbox
  * Inspect Deployments
  * Enter Mission Control

### Hero interaction

Center-stage command field:
**"What do you want to change, inspect, or run?"**

### Secondary content

* Suggested actions from Mama AI
* Recent organization changes
* Most active teams / sites / fleets
* Pending deployment gates

---

## Screen A2 - Executable Org Canvas

### Purpose

The core visual environment for building and running the company.

### Mental model

An advanced org-chart-like spatial canvas that supports:

* units
* teams
* roles
* principals
* AI agents
* software services
* workflows
* systems
* connectors
* sites
* assets / fleets
* approvals
* escalation routes
* authority edges

### Visual layers toggle

User can switch layers on/off:

* Org Structure
* Authority
* Workflow
* Systems
* Sites & Assets
* Policy Boundaries
* Jurisdictions
* Budget
* Conformance
* Deployments

### Node types

* Company
* Business Unit
* Team
* Role
* Human Principal
* AI Agent
* Service
* Workflow
* Approval Gate
* Policy Cluster
* Connector/System
* Site
* Fleet
* Asset
* Incident Zone
* Deployment Group

### Core actions

* add node
* connect node
* drag and regroup
* open subcanvas
* inspect lineage
* ask Mama AI about node
* simulate mutation
* compile selected region
* activate selected region
* freeze selected region

### Right inspector for a selected node

Shows:

* canonical type
* authority basis
* policy basis
* runtime state
* linked transactions
* linked deployments
* linked incidents
* conformance state
* evidence links
* allowed actions

### 2030 interaction features

* semantic zoom
* time scrubber for historical and future planned states
* live pulse indicators for active execution
* soft holographic layer transitions
* graph-aware snapping and auto-layout
* AI-generated grouping / clustering suggestions
* instant subgraph expansion

---

## Screen A3 - Node / Entity Studio

### Purpose

Deep configuration of any entity selected on canvas.

### Tabs

* Overview
* Identity
* Authority
* Policies
* Budgets
* Systems
* Runtime
* Deployments
* Evidence
* History

### Use cases

* Configure a team
* Configure an AI agent
* Configure a site
* Configure a fleet
* Configure a workflow
* Configure a principal

### Design rule

Settings must be highly understandable, not old-school enterprise forms.
Use structured cards, linked objects, human-readable summaries, and side-by-side diffs.

---

## Screen A4 - Genome Editor

### Purpose

Structured editing of OrgGenome.

### Dual-mode layout

Left: visual hierarchy / tree
Center: structured editable sections
Right: compiler validation / lineage / impact preview

### Sections

* Organizational identity
* Mission and objectives
* Role lattice
* Authority topology
* Budget graph
* Jurisdiction matrix
* Connector bindings
* Oversight rules
* Deployment targets
* Memory and data governance
* Safety constraints

### Actions

* validate
* draft mutation
* compare to live phenotype
* run simulation
* submit for ratification

---

## Screen A5 - Authority Graph Studio

### Purpose

Visualize and edit who can act, delegate, approve, escalate, override, or veto.

### Main visuals

* directed graph
* edge types color-coded by authority class
* risk badges
* budget authority markers
* veto / SoD nodes
* break-glass channels

### Key actions

* inspect authority chain
* view delegated scope
* identify shadow authority
* run SoD validation
* propose narrowing or expansion

---

## Screen A6 - Policy Composer

### Purpose

Compose policy bundles and overlays.

### Main model

* P0 ceilings
* P1 organizational policies
* P2 overlays

### UI blocks

* policy library
* active policy bundle
* local overlays
* conflicts panel
* jurisdictions panel
* runtime impact preview

### Critical feature

Every policy change shows:

* affected units
* affected workflows
* affected deployments
* affected sites/assets
* required approvals

---

## Screen A7 - Budget Graph Studio

### Purpose

Visualize and manage budget authority as a first-class organizational topology.

### Shows

* budget sources
* allocations
* team ceilings
* workflow ceilings
* approval thresholds
* burn state
* incident throttles

### Actions

* model budget mutation
* constrain authority by budget
* simulate capital routing changes

---

## Screen A8 - Jurisdiction Matrix

### Purpose

Make geography, sovereignty, compliance, and local rules visible and operable.

### Layout

Rows:

* regions / countries / sovereign zones / sites
  Columns:
* data residency
* labor rules
* finance rules
* approval rules
* site restrictions
* transfer rules
* reporting requirements
* special overlays

### Features

* conflict highlighting
* impossible-state warnings
* runtime execution implications
* deployment eligibility view

---

## Screen A9 - Mutation Planner

### Purpose

Plan and review organization changes before activation.

### Layout

Three-column:
Left - current state
Center - proposed mutation diff
Right - impact and rollout plan

### Impact categories

* authority
* policy
* workflow
* budget
* site/fleet
* deployment
* conformance
* approvals required

### Actions

* save draft
* request Mama AI refinement
* run simulation
* request approvals
* schedule rollout

---

## Screen A10 - Compile Preview

### Purpose

Pre-activation compiler output inspection.

### Shows

* compile status
* warnings
* hard errors
* unresolved ambiguities
* conformance forecast
* deployment forecast
* policy conflicts
* authority conflicts
* jurisdiction issues

### Critical interaction

Each warning or error should be clickable and jump user to the exact object or canvas region.

---

## Screen A11 - Activation Console

### Purpose

Activate new compiled organization state.

### Features

* activate whole org or scoped region
* canary / staged rollout
* site-by-site rollout
* team-by-team rollout
* automatic rollback window
* linked approvals
* linked simulations

---

# B. Mama AI surfaces

## Screen B1 - Mama AI Full Chat

### Purpose

The conversational command center.

### Layout

* Left: threaded sessions / contexts
* Center: active conversation with multi-step execution previews
* Right: object cards, action previews, evidence, compile plans

### Chat capabilities

Mama AI can:

* explain the company state
* generate structures
* propose mutations
* open or focus canvas areas
* build workflows
* draft approvals
* summarize incidents
* run diagnostics
* prepare deployment plans
* compare phenotype vs genome
* orchestrate human and machine work

### Critical rule

All non-trivial actions must materialize into visible objects or plans, never remain hidden in chat.

---

## Screen B2 - Mama AI Sidecar

### Purpose

Persistent assistant embedded beside canvas or operations screens.

### Uses

* answer context-aware questions
* propose fixes
* summarize selected node
* auto-complete edits
* explain evidence / conformance
* generate substructures from selection

---

## Screen B3 - Voice / Ambient Mama AI

### Purpose

Hands-free interaction for operations and physical-site contexts.

### Use cases

* supervisors in live operations
* incident management
* warehouse / field use
* command review

### Rules

Voice can initiate and inspect, but high-risk actions still require explicit structured confirmation.

---

# C. Inbox and arbitration

## Screen C1 - Unified Action Inbox

### Purpose

All pending human decisions in one operational queue.

### Categories

* Approvals
* HOTL Escalations
* Deployment Gates
* Mutations
* Safety Holds
* Incident Decisions
* Jurisdiction Conflicts

### Default columns

* severity
* object / scope
* requested action
* source actor
* why surfaced
* timer / SLA
* recommended resolver
* current state

---

## Screen C2 - Approval Detail

### Purpose

High-trust decision screen.

### Layout

* Requested change / action
* Object diff / impact
* policy basis
* authority basis
* evidence snapshot
* linked simulation or replay
* approve / deny / modify / escalate

---

## Screen C3 - HOTL Escalation Console

### Purpose

Resolve uncertainty or blocked physical/digital execution.

### Shows

* source asset / agent / workflow
* current hold reason
* context bundle
* camera / telemetry / state summary
* allowed intervention scope
* timer
* safe options

### Actions

* approve scoped continuation
* reroute
* remote intervene
* freeze
* abort
* escalate further

---

# D. Operations

## Screen D1 - Mission Control

### Purpose

The live company control tower.

### Main widgets

* live execution stream
* active workflows
* current incidents
* conformance state map
* site/fleet status
* deployment wave status
* org health ribbon

### Layout

Should feel cinematic and alive without becoming noisy.

---

## Screen D2 - Workflow Orchestrator

### Purpose

Manage cross-human / agent / service / robot workflows.

### Views

* graph view
* board view
* timeline view
* handoff view

### Shows

* current owner
* next step
* blocked reason
* approvals
* evidence state
* linked systems/sites/assets

---

## Screen D3 - Team Operations View

### Purpose

Operational control at team or unit level.

### Shows

* team topology
* active work
* assigned agents
* human owners
* authority state
* budget burn
* local conformance
* incidents

---

## Screen D4 - Site Console

### Purpose

Control a physical or logical site.

### Main views

* site map / zones
* active assets
* active human operators
* current workflows
* safety state
* deployment state
* incident state

---

## Screen D5 - Fleet Console

### Purpose

Run fleets as operational groups.

### Shows

* asset health
* active tasks
* version lineage
* current envelopes
* route/task allocation
* degraded units
* pending maintenance
* policy state

---

## Screen D6 - Asset Console

### Purpose

Inspect one robot / edge asset / controlled system.

### Shows

* identity
* current task
* capability envelope
* model/policy version
* telemetry
* command history
* allowed next actions
* evidence links

---

## Screen D7 - Incident Command

### Purpose

Centralized response for serious issues.

### Features

* incident timeline
* impacted scopes
* active freezes
* responders
* evidence
* recovery paths
* communications log
* linked mutation / rollback proposals

---

# E. Deployments

## Screen E1 - Deployment Center

### Purpose

All organization, model, policy, workflow, site, and fleet rollouts.

### Shows

* current deployments
* pending approvals
* rollout waves
* canary state
* rollback windows
* failed activations

---

## Screen E2 - Rollout Wave Manager

### Purpose

Visual staged activation.

### Features

* cohort segmentation
* drag reordering of waves
* success criteria
* halt conditions
* auto rollback thresholds

---

## Screen E3 - Version Lineage Explorer

### Purpose

See exactly what is running where and why.

### Shows

* model version
* policy bundle version
* genome activation version
* simulation basis
* approval lineage
* site/fleet targeting

---

# F. Conformance

## Screen F1 - Phenotype Overview

### Purpose

Top-level phenotype conformance view.

### Shows

* healthy / degraded / divergent / unknown / frozen
* by company / unit / workflow / site / asset

---

## Screen F2 - Conformance Delta Explorer

### Purpose

Compare intended vs actual state.

### Compare dimensions

* authority
* workflows
* budgets
* sites
* assets
* deployments
* policies
* jurisdictions

---

## Screen F3 - Drift Explorer

### Purpose

Analyze why divergence happened.

### Types

* authority drift
* policy drift
* budget drift
* deployment drift
* phenotype divergence
* site divergence

---

# G. Evidence and replay

## Screen G1 - Replay Center

### Purpose

Replay any action, workflow, mutation, deployment, incident, or actuation chain.

### Views

* timeline replay
* causal graph replay
* state delta replay
* media/telemetry replay where relevant

---

## Screen G2 - Evidence Inspector

### Purpose

See evidence attached to any object.

### Shows

* receipts
* approvals
* transactions
* proofs
* telemetry bundles
* exports
* signatures

---

## Screen G3 - Export Center

### Purpose

Generate regulator / audit / customer / legal export packages.

### Export types

* transaction slice
* incident slice
* deployment slice
* conformance report
* jurisdiction profile export

---

# H. Admin

## Screen H1 - Principal Registry

### Purpose

Manage humans, agents, services, assets.

## Screen H2 - Trust and Identity

### Purpose

Keys, trust roots, attestation, role bindings.

## Screen H3 - Integration Hub

### Purpose

Connectors, execution adapters, external systems.

## Screen H4 - Sovereignty Center

### Purpose

Residency, region control, transfer policy.

## Screen H5 - Safety Profiles

### Purpose

Actuation and hazard policy controls.

---

# Core reusable components

## 1. Universal Inspector

Used everywhere.
Shows:

* identity
* authority
* policy
* runtime
* evidence
* history
* allowed actions

## 2. Context Ribbon

At top of major panels:

* object type
* scope
* environment
* conformance state
* risk level
* active authority source

## 3. Evidence Drawer

Slide-up or side panel with proof artifacts.

## 4. Diff Viewer

For genome, mutation, deployment, authority, phenotype changes.

## 5. Live Activity Stream

Global execution/event feed.

## 6. Simulation Result Viewer

Readable, visual, and actionable.

## 7. Safe Action Bar

Only shows actions actually allowed in current scope.

---

# Role-adaptive experiences

## Executive / Founder

Primary screens:

* Studio Home
* Mission Control
* Mutation Planner
* Phenotype Overview
* Evidence exports

## Team Operator

Primary screens:

* Inbox
* Workflow Orchestrator
* Team Operations
* Mama AI Sidecar

## Governance / Compliance

Primary screens:

* Approval Detail
* Policy Composer
* Jurisdiction Matrix
* Evidence Inspector
* Export Center

## Org Architect

Primary screens:

* Canvas
* Genome Editor
* Authority Graph Studio
* Compile Preview
* Activation Console

## Site / Fleet Supervisor

Primary screens:

* Site Console
* Fleet Console
* Asset Console
* HOTL Escalation Console
* Incident Command

---

# UX quality bar - 2030 standard

The experience should feel:

* premium and spatial
* deeply automated
* radically clear
* evidence-native
* graph-native
* low-friction but high-trust
* cinematic in motion but not ornamental
* as advanced as a next-generation command environment, not as a generic enterprise app

The user should feel:

* total control,
* total visibility,
* high leverage,
* high confidence,
* and zero ambiguity about what is real, what is proposed, and what is allowed.

---

# Final product framing

HELM Studio is the unified environment where Mama AI and the executable organization meet.

Mama AI is the intelligence and orchestration layer.
Canvas is the spatial and structural layer.
Mission Control is the operational layer.
Compiler Studio is the organizational design layer.
Operations is the execution layer.
Conformance and Evidence are the truth layers.

This is the product shell that can actually hold a Stage 5 HELM system without fragmenting into separate tools.
