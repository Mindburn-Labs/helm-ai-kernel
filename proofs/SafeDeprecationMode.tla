---- MODULE SafeDeprecationMode ----
EXTENDS Naturals, Sequences

CONSTANTS Hazards, QuorumThreshold

VARIABLES state, continuityFresh, capsuleValid, quorumMet, dispatched, widened

States == {"normal", "terminal_freeze", "deprecated_readonly", "degraded_narrowing", "capsule_active"}

Init ==
  /\ state = "normal"
  /\ continuityFresh = FALSE
  /\ capsuleValid = FALSE
  /\ quorumMet = FALSE
  /\ dispatched = FALSE
  /\ widened = FALSE

DeadManExpired ==
  /\ state = "normal"
  /\ state' = "terminal_freeze"
  /\ UNCHANGED <<continuityFresh, capsuleValid, quorumMet, dispatched, widened>>

TrustFailure ==
  /\ state = "normal"
  /\ state' = "deprecated_readonly"
  /\ UNCHANGED <<continuityFresh, capsuleValid, quorumMet, dispatched, widened>>

RecoverableDecay ==
  /\ state = "normal"
  /\ state' = "degraded_narrowing"
  /\ UNCHANGED <<continuityFresh, capsuleValid, quorumMet, dispatched, widened>>

ProveContinuity ==
  /\ state = "degraded_narrowing"
  /\ continuityFresh' = TRUE
  /\ UNCHANGED <<state, capsuleValid, quorumMet, dispatched, widened>>

ValidateCapsule ==
  /\ state = "degraded_narrowing"
  /\ continuityFresh
  /\ capsuleValid' = TRUE
  /\ widened' = FALSE
  /\ UNCHANGED <<state, continuityFresh, quorumMet, dispatched>>

MeetQuorum ==
  /\ state = "degraded_narrowing"
  /\ continuityFresh
  /\ capsuleValid
  /\ quorumMet' = TRUE
  /\ UNCHANGED <<state, continuityFresh, capsuleValid, dispatched, widened>>

ActivateCapsule ==
  /\ state = "degraded_narrowing"
  /\ continuityFresh
  /\ capsuleValid
  /\ quorumMet
  /\ state' = "capsule_active"
  /\ UNCHANGED <<continuityFresh, capsuleValid, quorumMet, dispatched, widened>>

Dispatch ==
  /\ state = "capsule_active"
  /\ ~dispatched
  /\ dispatched' = TRUE
  /\ UNCHANGED <<state, continuityFresh, capsuleValid, quorumMet, widened>>

Hold ==
  /\ state \in {"terminal_freeze", "deprecated_readonly"} \/ (state = "capsule_active" /\ dispatched)
  /\ UNCHANGED <<state, continuityFresh, capsuleValid, quorumMet, dispatched, widened>>

Next ==
  \/ DeadManExpired
  \/ TrustFailure
  \/ RecoverableDecay
  \/ ProveContinuity
  \/ ValidateCapsule
  \/ MeetQuorum
  \/ ActivateCapsule
  \/ Dispatch
  \/ Hold

Spec == Init /\ [][Next]_<<state, continuityFresh, capsuleValid, quorumMet, dispatched, widened>>

NoMutationInTerminalFreeze == state = "terminal_freeze" => dispatched = FALSE
NoReadonlyDispatch == state = "deprecated_readonly" => dispatched = FALSE
NoWidening == widened = FALSE
NoActivationFromStaleContinuity == state = "capsule_active" => continuityFresh
NoDispatchBeforeQuorum == dispatched => quorumMet /\ capsuleValid /\ continuityFresh

THEOREM Spec => []NoMutationInTerminalFreeze
THEOREM Spec => []NoReadonlyDispatch
THEOREM Spec => []NoWidening
THEOREM Spec => []NoActivationFromStaleContinuity
THEOREM Spec => []NoDispatchBeforeQuorum

====
