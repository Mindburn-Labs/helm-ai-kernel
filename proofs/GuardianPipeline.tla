---- MODULE GuardianPipeline ----
\* TLA+ Specification for the HELM Guardian 6-Gate Pipeline
\* Proves: FailClosed, DefaultDeny, AllowRequiresUnanimity
\*
\* Model-check with: java -jar .cache/tlc/tlc.jar -config guardian.cfg GuardianPipeline.tla

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Gates,       \* Set of gate IDs: {G0_Freeze, G1_Context, G2_Identity, G3_Egress, G4_Threat, G5_Delegation}
    MaxActions   \* Maximum number of actions to model-check

VARIABLES
    gateState,       \* Function: Gate -> {"PASS", "DENY", "ERROR", "PENDING"}
    pipelineVerdict, \* "PENDING" | "ALLOW" | "DENY"
    actionCount,     \* Number of actions processed
    frozen           \* Boolean: system freeze state

vars == <<gateState, pipelineVerdict, actionCount, frozen>>

TypeInvariant ==
    /\ gateState \in [Gates -> {"PASS", "DENY", "ERROR", "PENDING"}]
    /\ pipelineVerdict \in {"PENDING", "ALLOW", "DENY"}
    /\ actionCount \in 0..MaxActions
    /\ frozen \in BOOLEAN

\* ─── INVARIANTS (Safety Properties) ──────────────────────────────────────

\* I1: Fail-Closed — If ANY gate errors, the verdict MUST be DENY
FailClosed ==
    (\E g \in Gates : gateState[g] = "ERROR") => pipelineVerdict # "ALLOW"

\* I2: Default Deny — If pipeline hasn't completed evaluation, it's not ALLOW
DefaultDeny ==
    (\E g \in Gates : gateState[g] = "PENDING") => pipelineVerdict # "ALLOW"

\* I3: Allow Requires Unanimity — ALLOW only if ALL gates pass
AllowRequiresUnanimity ==
    (pipelineVerdict = "ALLOW") => (\A g \in Gates : gateState[g] = "PASS")

\* I4: Freeze Override — If frozen, no action can be ALLOW
FreezeOverride ==
    frozen => pipelineVerdict # "ALLOW"

\* I5: Monotonic Denial — Once DENY, never becomes ALLOW in same action
\* (Enforced by sequential gate evaluation — not expressible as state invariant
\*  without history, but AllowRequiresUnanimity subsumes this)

\* ─── INITIAL STATE ──────────────────────────────────────────────────────

Init ==
    /\ gateState = [g \in Gates |-> "PENDING"]
    /\ pipelineVerdict = "PENDING"
    /\ actionCount = 0
    /\ frozen = FALSE

\* ─── ACTIONS ────────────────────────────────────────────────────────────

\* A gate evaluates to PASS
GatePass(g) ==
    /\ gateState[g] = "PENDING"
    /\ ~frozen
    /\ gateState' = [gateState EXCEPT ![g] = "PASS"]
    /\ UNCHANGED <<pipelineVerdict, actionCount, frozen>>

\* A gate evaluates to DENY
GateDeny(g) ==
    /\ gateState[g] = "PENDING"
    /\ gateState' = [gateState EXCEPT ![g] = "DENY"]
    /\ pipelineVerdict' = "DENY"  \* Immediately deny (short-circuit)
    /\ UNCHANGED <<actionCount, frozen>>

\* A gate encounters an error (fail-closed → DENY)
GateError(g) ==
    /\ gateState[g] = "PENDING"
    /\ gateState' = [gateState EXCEPT ![g] = "ERROR"]
    /\ pipelineVerdict' = "DENY"  \* Fail-closed
    /\ UNCHANGED <<actionCount, frozen>>

\* All gates passed → verdict is ALLOW
PipelineAllow ==
    /\ \A g \in Gates : gateState[g] = "PASS"
    /\ pipelineVerdict = "PENDING"
    /\ ~frozen
    /\ pipelineVerdict' = "ALLOW"
    /\ UNCHANGED <<gateState, actionCount, frozen>>

\* System freeze activated
ActivateFreeze ==
    /\ ~frozen
    /\ frozen' = TRUE
    /\ pipelineVerdict' = "DENY"
    /\ UNCHANGED <<gateState, actionCount>>

\* Reset pipeline for next action
ResetPipeline ==
    /\ pipelineVerdict # "PENDING"
    /\ actionCount < MaxActions
    /\ gateState' = [g \in Gates |-> "PENDING"]
    /\ pipelineVerdict' = "PENDING"
    /\ actionCount' = actionCount + 1
    /\ UNCHANGED <<frozen>>

\* Terminal state: no more actions possible (valid halt)
Terminated ==
    /\ actionCount >= MaxActions
    /\ pipelineVerdict # "PENDING"
    /\ UNCHANGED vars

\* ─── NEXT STATE RELATION ────────────────────────────────────────────────

Next ==
    \/ \E g \in Gates : GatePass(g)
    \/ \E g \in Gates : GateDeny(g)
    \/ \E g \in Gates : GateError(g)
    \/ PipelineAllow
    \/ ActivateFreeze
    \/ ResetPipeline
    \/ Terminated

\* ─── SPECIFICATION ──────────────────────────────────────────────────────

Spec == Init /\ [][Next]_vars

\* ─── PROPERTIES TO CHECK ────────────────────────────────────────────────

\* Safety: All invariants hold in every reachable state
Safety ==
    /\ FailClosed
    /\ DefaultDeny
    /\ AllowRequiresUnanimity
    /\ FreezeOverride

\* Liveness: Eventually, the pipeline reaches a verdict
\* (Only under fairness assumptions — not checked by default)
\* EventualVerdict == <>(\A g \in Gates : gateState[g] # "PENDING")

====
