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
    frozen,          \* Boolean: system freeze state
    taintSet,        \* Set of ClawGuard-style taint labels on current effect
    egressRequested  \* Boolean: current effect attempts outbound egress

vars == <<gateState, pipelineVerdict, actionCount, frozen, taintSet, egressRequested>>

TypeInvariant ==
    /\ gateState \in [Gates -> {"PASS", "DENY", "ERROR", "PENDING"}]
    /\ pipelineVerdict \in {"PENDING", "ALLOW", "DENY"}
    /\ actionCount \in 0..MaxActions
    /\ frozen \in BOOLEAN
    /\ taintSet \subseteq {"PII", "CREDENTIAL", "SECRET", "TOOL_OUTPUT", "USER_INPUT", "EXTERNAL"}
    /\ egressRequested \in BOOLEAN

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

\* I6: ClawGuard taint safety — sensitive taint may not leave trust boundary
SensitiveTaint == {"PII", "CREDENTIAL", "SECRET"}

TaintSafeEgress ==
    (egressRequested /\ (taintSet \cap SensitiveTaint # {})) => pipelineVerdict # "ALLOW"

\* I5: Monotonic Denial — Once DENY, never becomes ALLOW in same action
\* (Enforced by sequential gate evaluation — not expressible as state invariant
\*  without history, but AllowRequiresUnanimity subsumes this)

\* ─── INITIAL STATE ──────────────────────────────────────────────────────

Init ==
    /\ gateState = [g \in Gates |-> "PENDING"]
    /\ pipelineVerdict = "PENDING"
    /\ actionCount = 0
    /\ frozen = FALSE
    /\ taintSet = {}
    /\ egressRequested = FALSE

\* ─── ACTIONS ────────────────────────────────────────────────────────────

\* A gate evaluates to PASS
GatePass(g) ==
    /\ gateState[g] = "PENDING"
    /\ ~frozen
    /\ gateState' = [gateState EXCEPT ![g] = "PASS"]
    /\ UNCHANGED <<pipelineVerdict, actionCount, frozen, taintSet, egressRequested>>

\* A gate evaluates to DENY
GateDeny(g) ==
    /\ gateState[g] = "PENDING"
    /\ gateState' = [gateState EXCEPT ![g] = "DENY"]
    /\ pipelineVerdict' = "DENY"  \* Immediately deny (short-circuit)
    /\ UNCHANGED <<actionCount, frozen, taintSet, egressRequested>>

\* A gate encounters an error (fail-closed → DENY)
GateError(g) ==
    /\ gateState[g] = "PENDING"
    /\ gateState' = [gateState EXCEPT ![g] = "ERROR"]
    /\ pipelineVerdict' = "DENY"  \* Fail-closed
    /\ UNCHANGED <<actionCount, frozen, taintSet, egressRequested>>

\* Mark current effect as carrying tainted data before execution.
MarkTaint(t) ==
    /\ pipelineVerdict = "PENDING"
    /\ t \in {"PII", "CREDENTIAL", "SECRET", "TOOL_OUTPUT", "USER_INPUT", "EXTERNAL"}
    /\ taintSet' = taintSet \cup {t}
    /\ UNCHANGED <<gateState, pipelineVerdict, actionCount, frozen, egressRequested>>

\* Current effect attempts outbound egress.
RequestEgress ==
    /\ pipelineVerdict = "PENDING"
    /\ egressRequested' = TRUE
    /\ UNCHANGED <<gateState, pipelineVerdict, actionCount, frozen, taintSet>>

\* Sensitive taint plus egress denies before ALLOW can be reached.
TaintEgressDeny ==
    /\ pipelineVerdict = "PENDING"
    /\ egressRequested
    /\ taintSet \cap SensitiveTaint # {}
    /\ pipelineVerdict' = "DENY"
    /\ UNCHANGED <<gateState, actionCount, frozen, taintSet, egressRequested>>

\* All gates passed → verdict is ALLOW
PipelineAllow ==
    /\ \A g \in Gates : gateState[g] = "PASS"
    /\ pipelineVerdict = "PENDING"
    /\ ~frozen
    /\ ~(egressRequested /\ (taintSet \cap SensitiveTaint # {}))
    /\ pipelineVerdict' = "ALLOW"
    /\ UNCHANGED <<gateState, actionCount, frozen, taintSet, egressRequested>>

\* System freeze activated
ActivateFreeze ==
    /\ ~frozen
    /\ frozen' = TRUE
    /\ pipelineVerdict' = "DENY"
    /\ UNCHANGED <<gateState, actionCount, taintSet, egressRequested>>

\* Reset pipeline for next action
ResetPipeline ==
    /\ pipelineVerdict # "PENDING"
    /\ actionCount < MaxActions
    /\ gateState' = [g \in Gates |-> "PENDING"]
    /\ pipelineVerdict' = "PENDING"
    /\ actionCount' = actionCount + 1
    /\ taintSet' = {}
    /\ egressRequested' = FALSE
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
    \/ \E t \in {"PII", "CREDENTIAL", "SECRET", "TOOL_OUTPUT", "USER_INPUT", "EXTERNAL"} : MarkTaint(t)
    \/ RequestEgress
    \/ TaintEgressDeny
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
    /\ TaintSafeEgress

\* Liveness: Eventually, the pipeline reaches a verdict
\* (Only under fairness assumptions — not checked by default)
\* EventualVerdict == <>(\A g \in Gates : gateState[g] # "PENDING")

====
