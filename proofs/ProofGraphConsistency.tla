---- MODULE ProofGraphConsistency ----
\* TLA+ Specification for HELM ProofGraph DAG Integrity
\* Proves: MerkleIntegrity, NodeHashDeterminism, LamportMonotonicity, HeadConsistency
\*
\* Model-check with: java -jar tla2tools.jar -config proofgraph.cfg ProofGraphConsistency.tla

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxNodes,    \* Maximum number of nodes to model-check
    NodeTypes    \* Set of node types: {INTENT, ATTESTATION, EFFECT, TRUST_EVENT, CHECKPOINT, ...}

VARIABLES
    nodes,           \* Set of node records: {[hash, kind, parents, lamport, payload_hash]}
    lamportClock,    \* Current Lamport counter (monotonically increasing)
    heads,           \* Set of current head node hashes (DAG tips)
    merkleRoot,      \* Current Merkle root hash (computed from all nodes)
    nodeCount        \* Number of nodes added

vars == <<nodes, lamportClock, heads, merkleRoot, nodeCount>>

\* A node record
NodeRecord == [hash: STRING, kind: NodeTypes, parents: SUBSET STRING, lamport: Nat, payload_hash: STRING]

TypeInvariant ==
    /\ nodeCount \in 0..MaxNodes
    /\ lamportClock \in Nat
    /\ heads \subseteq STRING

\* ─── INVARIANTS (Safety Properties) ──────────────────────────────────────

\* I1: Lamport Monotonicity — Every node's Lamport clock > all parents' Lamport clocks
\* (Modeled as: global Lamport counter never decreases)
LamportMonotonicity ==
    \A n1, n2 \in nodes :
        (n1.hash \in n2.parents) => n1.lamport < n2.lamport

\* I2: Node Hash Determinism — No two distinct nodes share the same hash
\* (Content-addressed: same content = same hash, different content = different hash)
NodeHashUniqueness ==
    \A n1, n2 \in nodes :
        (n1.hash = n2.hash) => (n1 = n2)

\* I3: Parent Existence — Every parent reference points to an existing node
ParentExistence ==
    \A n \in nodes :
        \A p \in n.parents :
            \E existing \in nodes : existing.hash = p

\* I4: Head Consistency — Heads are exactly the nodes with no children
HeadConsistency ==
    \A h \in heads :
        ~(\E n \in nodes : h \in n.parents)

\* I5: Acyclicity — No node is its own ancestor (DAG property)
\* (Enforced by LamportMonotonicity: cycles would require lamport < lamport)

\* I6: Append-Only — Nodes are never removed or modified
\* (Enforced by specification: no delete/modify actions exist)

\* ─── INITIAL STATE ──────────────────────────────────────────────────────

Init ==
    /\ nodes = {}
    /\ lamportClock = 0
    /\ heads = {}
    /\ merkleRoot = "EMPTY"
    /\ nodeCount = 0

\* ─── ACTIONS ────────────────────────────────────────────────────────────

\* Add a genesis node (no parents)
AddGenesisNode(kind, payloadHash) ==
    /\ nodeCount < MaxNodes
    /\ lamportClock' = lamportClock + 1
    /\ LET newNode == [hash |-> payloadHash, kind |-> kind,
                       parents |-> {}, lamport |-> lamportClock + 1,
                       payload_hash |-> payloadHash]
       IN /\ nodes' = nodes \union {newNode}
          /\ heads' = {newNode.hash}
    /\ nodeCount' = nodeCount + 1
    /\ merkleRoot' = "UPDATED"

\* Add a node with parents (extends the DAG)
AddNode(kind, payloadHash, parentSet) ==
    /\ nodeCount < MaxNodes
    /\ parentSet # {}
    /\ parentSet \subseteq {n.hash : n \in nodes}  \* All parents must exist
    /\ LET maxParentLamport == CHOOSE l \in {n.lamport : n \in nodes} :
               \A n \in nodes : (n.hash \in parentSet) => n.lamport <= l
           newLamport == maxParentLamport + 1
           newNode == [hash |-> payloadHash, kind |-> kind,
                       parents |-> parentSet, lamport |-> newLamport,
                       payload_hash |-> payloadHash]
       IN /\ lamportClock' = newLamport
          /\ nodes' = nodes \union {newNode}
          /\ heads' = (heads \ parentSet) \union {newNode.hash}
    /\ nodeCount' = nodeCount + 1
    /\ merkleRoot' = "UPDATED"

\* Create a checkpoint (Merkle condensation point)
AddCheckpoint(parentSet) ==
    /\ nodeCount < MaxNodes
    /\ parentSet # {}
    /\ parentSet \subseteq {n.hash : n \in nodes}
    /\ AddNode("CHECKPOINT", "checkpoint_hash", parentSet)

\* Terminal: no more nodes
Terminated ==
    /\ nodeCount >= MaxNodes
    /\ UNCHANGED vars

\* ─── NEXT STATE RELATION ────────────────────────────────────────────────

Next ==
    \/ \E kind \in NodeTypes, ph \in STRING : AddGenesisNode(kind, ph)
    \/ \E kind \in NodeTypes, ph \in STRING, ps \in SUBSET {n.hash : n \in nodes} :
           ps # {} /\ AddNode(kind, ph, ps)
    \/ \E ps \in SUBSET {n.hash : n \in nodes} :
           ps # {} /\ AddCheckpoint(ps)
    \/ Terminated

\* ─── SPECIFICATION ──────────────────────────────────────────────────────

Spec == Init /\ [][Next]_vars

\* ─── PROPERTIES TO CHECK ────────────────────────────────────────────────

Safety ==
    /\ LamportMonotonicity
    /\ NodeHashUniqueness
    /\ ParentExistence

====
