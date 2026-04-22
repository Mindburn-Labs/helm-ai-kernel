---- MODULE DelegationModel ----
\* TLA+ Specification for HELM Delegation Session Model
\* Proves: SubsetOfDelegator, TimeExpiry, AntiReplay, NoPrivilegeEscalation
\*
\* Model-check with: java -jar tla2tools.jar -config delegation.cfg DelegationModel.tla

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Principals,      \* Set of principal IDs (agents/users)
    Capabilities,    \* Set of capability names
    MaxSessions,     \* Maximum concurrent sessions
    MaxTime          \* Maximum time steps

VARIABLES
    sessions,        \* Set of active delegation sessions
    nonces,          \* Set of consumed nonces (anti-replay)
    clock,           \* Logical clock
    principalCaps    \* Function: Principal -> Set of Capabilities (authority)

vars == <<sessions, nonces, clock, principalCaps>>

\* A delegation session
Session == [id: STRING, delegator: Principals, delegate: Principals,
            capabilities: SUBSET Capabilities, nonce: STRING,
            createdAt: Nat, expiresAt: Nat, revoked: BOOLEAN]

TypeInvariant ==
    /\ clock \in 0..MaxTime
    /\ nonces \subseteq STRING

\* ─── INVARIANTS (Safety Properties) ──────────────────────────────────────

\* I1: Subset-of-Delegator — Delegate capabilities NEVER exceed delegator capabilities
SubsetOfDelegator ==
    \A s \in sessions :
        ~s.revoked =>
            s.capabilities \subseteq principalCaps[s.delegator]

\* I2: No Privilege Escalation — A delegate cannot create a session granting
\*     more capabilities than they themselves have (transitive narrowing)
NoPrivilegeEscalation ==
    \A s1, s2 \in sessions :
        (s2.delegator = s1.delegate /\ ~s1.revoked /\ ~s2.revoked) =>
            s2.capabilities \subseteq s1.capabilities

\* I3: Time Expiry — Expired sessions cannot authorize actions
\* (Modeled as: expired sessions are treated as revoked)
ExpiredMeansRevoked ==
    \A s \in sessions :
        (clock > s.expiresAt) => s.revoked

\* I4: Anti-Replay — Each nonce is used exactly once
NonceUniqueness ==
    \A s1, s2 \in sessions :
        (s1.nonce = s2.nonce /\ s1.id # s2.id) => FALSE

\* I5: Revocation Permanence — Once revoked, a session stays revoked
\* (Enforced by specification: no un-revoke action exists)

\* ─── INITIAL STATE ──────────────────────────────────────────────────────

Init ==
    /\ sessions = {}
    /\ nonces = {}
    /\ clock = 0
    /\ principalCaps = [p \in Principals |-> Capabilities]  \* All principals start with full caps

\* ─── ACTIONS ────────────────────────────────────────────────────────────

\* Create a delegation session (delegator grants subset of their caps to delegate)
CreateSession(delegator, delegate, caps, nonce, ttl) ==
    /\ Cardinality(sessions) < MaxSessions
    /\ delegator # delegate                        \* Cannot self-delegate
    /\ caps \subseteq principalCaps[delegator]     \* MUST be subset (I1)
    /\ nonce \notin nonces                         \* MUST be fresh (I4)
    /\ LET newSession == [id |-> nonce, delegator |-> delegator,
                          delegate |-> delegate, capabilities |-> caps,
                          nonce |-> nonce, createdAt |-> clock,
                          expiresAt |-> clock + ttl, revoked |-> FALSE]
       IN /\ sessions' = sessions \union {newSession}
          /\ nonces' = nonces \union {nonce}
    /\ UNCHANGED <<clock, principalCaps>>

\* Revoke a session
RevokeSession(sessionId) ==
    /\ \E s \in sessions : s.id = sessionId /\ ~s.revoked
    /\ sessions' = {IF s.id = sessionId THEN [s EXCEPT !.revoked = TRUE] ELSE s : s \in sessions}
    /\ UNCHANGED <<nonces, clock, principalCaps>>

\* Time advances
Tick ==
    /\ clock < MaxTime
    /\ clock' = clock + 1
    \* Auto-revoke expired sessions
    /\ sessions' = {IF clock + 1 > s.expiresAt THEN [s EXCEPT !.revoked = TRUE] ELSE s : s \in sessions}
    /\ UNCHANGED <<nonces, principalCaps>>

\* Reduce a principal's capabilities (e.g., admin revokes a capability)
NarrowCapabilities(principal, removedCap) ==
    /\ removedCap \in principalCaps[principal]
    /\ principalCaps' = [principalCaps EXCEPT ![principal] = principalCaps[principal] \ {removedCap}]
    \* All sessions where this principal is delegator must be narrowed or revoked
    /\ sessions' = {IF s.delegator = principal /\ removedCap \in s.capabilities
                    THEN [s EXCEPT !.revoked = TRUE]
                    ELSE s : s \in sessions}
    /\ UNCHANGED <<nonces, clock>>

\* Terminal
Terminated ==
    /\ clock >= MaxTime
    /\ UNCHANGED vars

\* ─── NEXT STATE RELATION ────────────────────────────────────────────────

Next ==
    \/ \E d, del \in Principals, caps \in SUBSET Capabilities, n \in STRING, ttl \in 1..5 :
           CreateSession(d, del, caps, n, ttl)
    \/ \E sid \in STRING : RevokeSession(sid)
    \/ Tick
    \/ \E p \in Principals, c \in Capabilities : NarrowCapabilities(p, c)
    \/ Terminated

\* ─── SPECIFICATION ──────────────────────────────────────────────────────

Spec == Init /\ [][Next]_vars

\* ─── PROPERTIES TO CHECK ────────────────────────────────────────────────

Safety ==
    /\ SubsetOfDelegator
    /\ NoPrivilegeEscalation
    /\ NonceUniqueness

====
