---- MODULE HelmKernel ----
\* TLA+ Formal Model for the HELM Kernel
\* This specifies the safety invariants for the Guardian → Executor pipeline.

EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Helper: Range of a sequence (set of all elements)
Range(s) == {s[i] : i \in 1..Len(s)}

CONSTANTS
    Principals,     \* Set of all principals (agents, humans)
    Tools,          \* Set of all available tools
    Policies        \* Set of all policies

VARIABLES
    proofGraph,     \* Sequence of ProofGraph nodes
    lamportClock,   \* Monotonically increasing Lamport counter
    decisions,      \* Set of active decision records
    receipts,       \* Set of generated receipts
    trustRoot       \* Set of trusted signing keys

\* Type invariant
TypeInvariant ==
    /\ lamportClock \in Nat
    /\ lamportClock >= 0

\* === SAFETY INVARIANTS ===

\* S1: Fail-Closed — No execution without a valid decision
FailClosed ==
    \A r \in receipts:
        \E d \in decisions: d.id = r.decisionId /\ d.verdict = "ALLOW"

\* S2: Monotonic Lamport — ProofGraph is strictly ordered
MonotonicLamport ==
    \A i \in 1..Len(proofGraph)-1:
        proofGraph[i].lamport < proofGraph[i+1].lamport

\* S3: Receipt Completeness — Every execution produces a receipt
ReceiptCompleteness ==
    \A e \in {n \in Range(proofGraph): n.kind = "EXECUTION"}:
        \E r \in receipts: r.executionNodeHash = e.nodeHash

\* S4: Principal Binding — Every node is bound to a principal
PrincipalBinding ==
    \A n \in Range(proofGraph):
        n.principal \in Principals

\* S5: Hash Chain Integrity — Every non-genesis node references valid parents
HashChainIntegrity ==
    \A i \in 2..Len(proofGraph):
        \E j \in 1..i-1:
            proofGraph[j].nodeHash \in proofGraph[i].parents

\* === STATE TRANSITIONS ===

\* Guardian evaluates a decision request
EvaluateDecision(principal, tool, action) ==
    /\ principal \in Principals
    /\ tool \in Tools
    /\ LET newLamport == lamportClock + 1
           decision == [
               id |-> "dec-" \o ToString(newLamport),
               principal |-> principal,
               tool |-> tool,
               action |-> action,
               verdict |-> IF action \in Policies THEN "ALLOW" ELSE "DENY",
               lamport |-> newLamport
           ]
       IN /\ lamportClock' = newLamport
          /\ decisions' = decisions \union {decision}
          /\ proofGraph' = Append(proofGraph, [
                nodeHash |-> "hash-" \o ToString(newLamport),
                kind |-> "DECISION",
                principal |-> principal,
                lamport |-> newLamport
             ])
          /\ UNCHANGED <<receipts, trustRoot>>

\* Executor runs an allowed effect
ExecuteEffect(decisionId) ==
    /\ \E d \in decisions:
        /\ d.id = decisionId
        /\ d.verdict = "ALLOW"
        /\ LET newLamport == lamportClock + 1
               receipt == [
                   decisionId |-> decisionId,
                   executionNodeHash |-> "hash-" \o ToString(newLamport),
                   lamport |-> newLamport
               ]
           IN /\ lamportClock' = newLamport
              /\ receipts' = receipts \union {receipt}
              /\ proofGraph' = Append(proofGraph, [
                    nodeHash |-> "hash-" \o ToString(newLamport),
                    kind |-> "EXECUTION",
                    principal |-> d.principal,
                    lamport |-> newLamport
                 ])
              /\ UNCHANGED <<decisions, trustRoot>>

\* === SPECIFICATION ===

Init ==
    /\ proofGraph = <<>>
    /\ lamportClock = 0
    /\ decisions = {}
    /\ receipts = {}
    /\ trustRoot = {}

Next ==
    \/ \E p \in Principals, t \in Tools, a \in {"read", "write", "execute"}:
        EvaluateDecision(p, t, a)
    \/ \E d \in decisions: ExecuteEffect(d.id)

Spec == Init /\ [][Next]_<<proofGraph, lamportClock, decisions, receipts, trustRoot>>

\* === PROPERTIES TO CHECK ===

Safety == FailClosed /\ MonotonicLamport /\ PrincipalBinding

\* State constraint for finite model checking
StateConstraint == lamportClock < 6

====
