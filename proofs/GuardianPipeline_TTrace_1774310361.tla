---- MODULE GuardianPipeline_TTrace_1774310361 ----
EXTENDS Sequences, TLCExt, Toolbox, GuardianPipeline_TEConstants, Naturals, TLC, GuardianPipeline

_expression ==
    LET GuardianPipeline_TEExpression == INSTANCE GuardianPipeline_TEExpression
    IN GuardianPipeline_TEExpression!expression
----

_trace ==
    LET GuardianPipeline_TETrace == INSTANCE GuardianPipeline_TETrace
    IN GuardianPipeline_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        actionCount = (3)
        /\
        gateState = ((G0_Freeze :> "DENY" @@ G1_Context :> "DENY" @@ G2_Identity :> "DENY" @@ G3_Egress :> "DENY" @@ G4_Threat :> "DENY" @@ G5_Delegation :> "DENY"))
        /\
        pipelineVerdict = ("DENY")
        /\
        frozen = (TRUE)
    )
----

_init ==
    /\ gateState = _TETrace[1].gateState
    /\ actionCount = _TETrace[1].actionCount
    /\ frozen = _TETrace[1].frozen
    /\ pipelineVerdict = _TETrace[1].pipelineVerdict
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ gateState  = _TETrace[i].gateState
        /\ gateState' = _TETrace[j].gateState
        /\ actionCount  = _TETrace[i].actionCount
        /\ actionCount' = _TETrace[j].actionCount
        /\ frozen  = _TETrace[i].frozen
        /\ frozen' = _TETrace[j].frozen
        /\ pipelineVerdict  = _TETrace[i].pipelineVerdict
        /\ pipelineVerdict' = _TETrace[j].pipelineVerdict

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("GuardianPipeline_TTrace_1774310361.json", _TETrace)

=============================================================================

 Note that you can extract this module `GuardianPipeline_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `GuardianPipeline_TEExpression.tla` file takes precedence 
  over the module `GuardianPipeline_TEExpression` below).

---- MODULE GuardianPipeline_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, GuardianPipeline_TEConstants, Naturals, TLC, GuardianPipeline

expression == 
    [
        \* To hide variables of the `GuardianPipeline` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        gateState |-> gateState
        ,actionCount |-> actionCount
        ,frozen |-> frozen
        ,pipelineVerdict |-> pipelineVerdict
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_gateStateUnchanged |-> gateState = gateState'
        
        \* Format the `gateState` variable as Json value.
        \* ,_gateStateJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(gateState)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_gateStateModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].gateState # _TETrace[s-1].gateState
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE GuardianPipeline_TETrace ----
\*EXTENDS IOUtils, GuardianPipeline_TEConstants, TLC, GuardianPipeline
\*
\*trace == IODeserialize("GuardianPipeline_TTrace_1774310361.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE GuardianPipeline_TETrace ----
EXTENDS GuardianPipeline_TEConstants, TLC, GuardianPipeline

trace == 
    <<
    ([actionCount |-> 0,gateState |-> (G0_Freeze :> "PENDING" @@ G1_Context :> "PENDING" @@ G2_Identity :> "PENDING" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "PENDING",frozen |-> FALSE]),
    ([actionCount |-> 0,gateState |-> (G0_Freeze :> "PASS" @@ G1_Context :> "PENDING" @@ G2_Identity :> "PENDING" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "PENDING",frozen |-> FALSE]),
    ([actionCount |-> 0,gateState |-> (G0_Freeze :> "PASS" @@ G1_Context :> "PASS" @@ G2_Identity :> "PENDING" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "PENDING",frozen |-> FALSE]),
    ([actionCount |-> 0,gateState |-> (G0_Freeze :> "PASS" @@ G1_Context :> "PASS" @@ G2_Identity :> "DENY" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "DENY",frozen |-> FALSE]),
    ([actionCount |-> 1,gateState |-> (G0_Freeze :> "PENDING" @@ G1_Context :> "PENDING" @@ G2_Identity :> "PENDING" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "PENDING",frozen |-> FALSE]),
    ([actionCount |-> 1,gateState |-> (G0_Freeze :> "DENY" @@ G1_Context :> "PENDING" @@ G2_Identity :> "PENDING" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "DENY",frozen |-> FALSE]),
    ([actionCount |-> 2,gateState |-> (G0_Freeze :> "PENDING" @@ G1_Context :> "PENDING" @@ G2_Identity :> "PENDING" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "PENDING",frozen |-> FALSE]),
    ([actionCount |-> 2,gateState |-> (G0_Freeze :> "PENDING" @@ G1_Context :> "PENDING" @@ G2_Identity :> "PENDING" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "DENY",frozen |-> TRUE]),
    ([actionCount |-> 3,gateState |-> (G0_Freeze :> "PENDING" @@ G1_Context :> "PENDING" @@ G2_Identity :> "PENDING" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "PENDING",frozen |-> TRUE]),
    ([actionCount |-> 3,gateState |-> (G0_Freeze :> "DENY" @@ G1_Context :> "PENDING" @@ G2_Identity :> "PENDING" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "DENY",frozen |-> TRUE]),
    ([actionCount |-> 3,gateState |-> (G0_Freeze :> "DENY" @@ G1_Context :> "DENY" @@ G2_Identity :> "PENDING" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "DENY",frozen |-> TRUE]),
    ([actionCount |-> 3,gateState |-> (G0_Freeze :> "DENY" @@ G1_Context :> "DENY" @@ G2_Identity :> "DENY" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "PENDING" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "DENY",frozen |-> TRUE]),
    ([actionCount |-> 3,gateState |-> (G0_Freeze :> "DENY" @@ G1_Context :> "DENY" @@ G2_Identity :> "DENY" @@ G3_Egress :> "PENDING" @@ G4_Threat :> "DENY" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "DENY",frozen |-> TRUE]),
    ([actionCount |-> 3,gateState |-> (G0_Freeze :> "DENY" @@ G1_Context :> "DENY" @@ G2_Identity :> "DENY" @@ G3_Egress :> "DENY" @@ G4_Threat :> "DENY" @@ G5_Delegation :> "PENDING"),pipelineVerdict |-> "DENY",frozen |-> TRUE]),
    ([actionCount |-> 3,gateState |-> (G0_Freeze :> "DENY" @@ G1_Context :> "DENY" @@ G2_Identity :> "DENY" @@ G3_Egress :> "DENY" @@ G4_Threat :> "DENY" @@ G5_Delegation :> "DENY"),pipelineVerdict |-> "DENY",frozen |-> TRUE])
    >>
----


=============================================================================

---- MODULE GuardianPipeline_TEConstants ----
EXTENDS GuardianPipeline

CONSTANTS G0_Freeze, G1_Context, G2_Identity, G3_Egress, G4_Threat, G5_Delegation

=============================================================================

---- CONFIG GuardianPipeline_TTrace_1774310361 ----
CONSTANTS
    Gates = { G0_Freeze , G1_Context , G2_Identity , G3_Egress , G4_Threat , G5_Delegation }
    MaxActions = 3
    G4_Threat = G4_Threat
    G3_Egress = G3_Egress
    G0_Freeze = G0_Freeze
    G1_Context = G1_Context
    G5_Delegation = G5_Delegation
    G2_Identity = G2_Identity

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Tue Mar 24 00:59:21 CET 2026