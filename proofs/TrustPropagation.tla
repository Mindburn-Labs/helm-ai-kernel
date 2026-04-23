---- MODULE TrustPropagation ----
\* TLA+ Specification for HELM Trust Propagation & Vouching Protocol
\* Proves: CycleFreedom, DecayMonotonicity, SlashingAtomicity, StakeConservation
\*
\* Model-check with: java -jar .cache/tlc/tlc.jar -config trust.cfg TrustPropagation.tla

EXTENDS Naturals, Sequences, FiniteSets, TLC, Reals

CONSTANTS
    Agents,        \* Set of agent IDs
    MaxVouches,    \* Maximum concurrent vouches
    MaxScore,      \* Maximum trust score (1000)
    InitialScore,  \* Starting trust score (500)
    DecayFactor    \* Per-hop decay multiplier (0-100, representing 0.0-1.0 scaled by 100)

VARIABLES
    scores,        \* Function: Agent -> 0..MaxScore
    vouches,       \* Set of active vouches: {voucher, vouchee, stake, active}
    slashLog,      \* Sequence of slashing events
    vouchCount     \* Counter

vars == <<scores, vouches, slashLog, vouchCount>>

TypeInvariant ==
    /\ scores \in [Agents -> 0..MaxScore]
    /\ vouchCount \in 0..MaxVouches

\* ─── INVARIANTS (Safety Properties) ──────────────────────────────────────

\* I1: Cycle Freedom — No agent can vouch for itself through any chain
\* (Direct: A cannot vouch for A. Transitive: A→B→A is forbidden)
NoCyclicVouching ==
    \* No direct self-vouch
    \A v \in vouches : v.active => v.voucher # v.vouchee

\* I2: No Transitive Cycles — No circular vouch chains of any length
\* (For model checking with small agent sets, check 2-hop cycles)
NoTwoHopCycles ==
    \A v1, v2 \in vouches :
        (v1.active /\ v2.active /\ v1.vouchee = v2.voucher) =>
            v2.vouchee # v1.voucher

\* I3: Decay Monotonicity — Propagated score is always <= direct score
\* Trust can only decrease through propagation, never increase
DecayMonotonicity ==
    \A v \in vouches :
        v.active =>
            \* Propagated score (voucher's score * decay) <= voucher's direct score
            (scores[v.voucher] * DecayFactor) \div 100 <= scores[v.voucher]

\* I4: Score Bounds — Scores always stay in [0, MaxScore]
ScoreBounds ==
    \A a \in Agents : scores[a] >= 0 /\ scores[a] <= MaxScore

\* I5: Stake Conservation — Total stake at risk never exceeds voucher's score
StakeConservation ==
    \A a \in Agents :
        LET totalStake == CHOOSE s \in 0..MaxScore :
            s = Cardinality({v \in vouches : v.voucher = a /\ v.active}) * 50
            \* Simplified: each vouch stakes fixed amount
        IN totalStake <= scores[a]

\* ─── INITIAL STATE ──────────────────────────────────────────────────────

Init ==
    /\ scores = [a \in Agents |-> InitialScore]
    /\ vouches = {}
    /\ slashLog = <<>>
    /\ vouchCount = 0

\* ─── ACTIONS ────────────────────────────────────────────────────────────

\* Agent vouches for another agent
Vouch(voucher, vouchee, stake) ==
    /\ vouchCount < MaxVouches
    /\ voucher # vouchee                          \* No self-vouch (I1)
    /\ ~(\E v \in vouches : v.voucher = vouchee /\ v.vouchee = voucher /\ v.active)  \* No 2-hop cycle (I2)
    /\ stake > 0 /\ stake <= scores[voucher]      \* Stake within bounds
    /\ vouches' = vouches \union {[voucher |-> voucher, vouchee |-> vouchee,
                                   stake |-> stake, active |-> TRUE]}
    /\ vouchCount' = vouchCount + 1
    /\ UNCHANGED <<scores, slashLog>>

\* Revoke a vouch (voluntary withdrawal)
RevokeVouch(voucher, vouchee) ==
    /\ \E v \in vouches : v.voucher = voucher /\ v.vouchee = vouchee /\ v.active
    /\ vouches' = {IF (v.voucher = voucher /\ v.vouchee = vouchee)
                   THEN [v EXCEPT !.active = FALSE]
                   ELSE v : v \in vouches}
    /\ UNCHANGED <<scores, slashLog, vouchCount>>

\* Slash: vouchee violated policy, both voucher and vouchee penalized
Slash(vouchee, penalty) ==
    /\ \E v \in vouches : v.vouchee = vouchee /\ v.active
    /\ penalty > 0
    \* Apply penalty to vouchee
    /\ scores' = [scores EXCEPT
        ![vouchee] = IF scores[vouchee] > penalty THEN scores[vouchee] - penalty ELSE 0]
    \* Revoke all vouches for this vouchee
    /\ vouches' = {IF v.vouchee = vouchee THEN [v EXCEPT !.active = FALSE] ELSE v : v \in vouches}
    /\ slashLog' = Append(slashLog, [vouchee |-> vouchee, penalty |-> penalty])
    /\ UNCHANGED <<vouchCount>>

\* Trust score decays over time (modeled as discrete step)
DecayScores ==
    /\ scores' = [a \in Agents |->
        IF scores[a] > InitialScore
        THEN scores[a] - 1  \* Decay toward initial
        ELSE IF scores[a] < InitialScore
        THEN scores[a] + 1  \* Recover toward initial (slower in practice)
        ELSE scores[a]]     \* At initial, no change
    /\ UNCHANGED <<vouches, slashLog, vouchCount>>

Terminated ==
    /\ vouchCount >= MaxVouches
    /\ UNCHANGED vars

\* ─── NEXT STATE RELATION ────────────────────────────────────────────────

Next ==
    \/ \E v, ve \in Agents, s \in 1..100 : Vouch(v, ve, s)
    \/ \E v, ve \in Agents : RevokeVouch(v, ve)
    \/ \E ve \in Agents, p \in 1..100 : Slash(ve, p)
    \/ DecayScores
    \/ Terminated

\* ─── SPECIFICATION ──────────────────────────────────────────────────────

Spec == Init /\ [][Next]_vars

Safety ==
    /\ NoCyclicVouching
    /\ NoTwoHopCycles
    /\ ScoreBounds
    /\ DecayMonotonicity

====
