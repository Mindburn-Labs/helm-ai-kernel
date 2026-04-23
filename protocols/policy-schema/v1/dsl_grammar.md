# Policy DSL Grammar v0

> Frozen EBNF for the CEL-like surface syntax compiled to PolicyIR bytecode.
> This grammar defines the authoring language — not the execution model.

## Evaluation Strategy

1. Modules in **canonical order**: jurisdiction, licenses, treasury, authority, data, tools, risk, contracts, simulation, merge
2. Rules by ascending **priority** (default 1000), then `rule_id` lexicographic
3. **Fail-fast**: first triggered `enforce` stops evaluation for that subject
4. `rewrite` emits structured ops into candidate delta (re-validated before acceptance)
5. `patch:` emits suggestions only (never auto-applied)
6. `fact("key")` returns typed value or `unknown`; comparisons against `unknown` are **compile-time errors** unless guarded by `known(fact("key"))`

## Compiler Limits

- Max boolean expression depth: **16**
- Max rules per module: **256**
- Max patch ops per template: **32**
- Max parameters per patch: **8**

## EBNF

```ebnf
PolicyBundle     ::= Header? Module+
Header           ::= "bundle" Identifier "{" "cpi:" HashRef "}"

Module           ::= "module" ModuleName "{" (TemplateDecl | Rule)+ "}"
ModuleName       ::= "jurisdiction" | "licenses" | "treasury" | "authority"
                    | "data" | "tools" | "risk" | "contracts" | "simulation" | "merge"

TemplateDecl     ::= "template" Identifier "{" PatchOps "}"

Rule             ::= "rule" Identifier RuleMeta? "{" Scope When Enforce Explain PatchBlock? "}"
RuleMeta         ::= "[" "priority" "=" IntLiteral "]"

Scope            ::= "scope:" FilterExpr
When             ::= "when:" BoolExpr
Enforce          ::= "enforce:" EnforceAction
Explain          ::= "explain:" ExplainSpec
PatchBlock       ::= "patch:" (PatchInvoke | PatchInvokeList)
PatchInvokeList  ::= "[" PatchInvoke ("," PatchInvoke)* "]"

FilterExpr       ::= TargetSpec ("in" JurisdictionSet)? ("tagged" TagSet)?
TargetSpec       ::= TargetType ("(" TargetPred ")")?
TargetType       ::= "node" | "edge" | "agent" | "capital_flow" | "data_flow"
TargetPred       ::= PredAtom ("and" PredAtom)*
PredAtom         ::= IdentPath Operator Literal

JurisdictionSet  ::= StringLiteral | "[" StringLiteral ("," StringLiteral)* "]"
TagSet           ::= StringLiteral | "[" StringLiteral ("," StringLiteral)* "]"

BoolExpr         ::= OrExpr
OrExpr           ::= AndExpr ("or" AndExpr)*
AndExpr          ::= NotExpr ("and" NotExpr)*
NotExpr          ::= ("not")? Primary
Primary          ::= "(" BoolExpr ")" | Condition

Condition        ::= Comparison | Call
Comparison       ::= Value Operator Value
Operator         ::= "==" | "!=" | ">" | "<" | ">=" | "<=" | "contains"

Value            ::= Literal | Ref | Call
Ref              ::= "delta." IdentPath | "snapshot." IdentPath
IdentPath        ::= Identifier ("." Identifier)*

Call             ::= FuncName "(" ArgList? ")"
FuncName         ::= "fact" | "known" | "has_primitive" | "has_tag" | "edge_type" | "node_type"

ArgList          ::= Arg ("," Arg)*
Arg              ::= Identifier "=" Literal | Literal

Literal          ::= StringLiteral | IntLiteral | MoneyLiteral | DurationLiteral | BoolLiteral
MoneyLiteral     ::= "money(" StringLiteral "," IntLiteral ")"
DurationLiteral  ::= "duration_ms(" IntLiteral ")"

EnforceAction    ::= "deny"
                   | "require_approval(" RoleId ")"
                   | "needs_facts(" KeyList ")"
                   | "rewrite(" PatchOps ")"

ExplainSpec      ::= ReasonCode ("," ArgList)?
ReasonCode       ::= Identifier ("." Identifier)+

KeyList          ::= StringLiteral | "[" StringLiteral ("," StringLiteral)* "]"
RoleId           ::= StringLiteral

PatchInvoke      ::= Identifier "(" ArgList? ")"
PatchOps         ::= "{" PatchOp+ "}"
PatchOp          ::= InsertNode | AttachPrimitive | InsertTransformer | AddGate | SetValve | AddTag

InsertNode       ::= "insert_node(" ArgList ")"
AttachPrimitive  ::= "attach_primitive(" ArgList ")"
InsertTransformer::= "insert_transformer(" ArgList ")"
AddGate          ::= "add_gate(" ArgList ")"
SetValve         ::= "set_valve(" ArgList ")"
AddTag           ::= "add_tag(" ArgList ")"
```

## Example: MiCA License Requirement

```
module licenses {
  template mica_license_patch {
    insert_node(type = "LICENSE", subtype = "MICA")
    attach_primitive(target = delta.node, primitive = "mica_license")
  }

  rule mica_required [priority = 100] {
    scope: agent(node_type == "ENTITY") in ["EU", "EEA"]
    when: not has_primitive(delta.node, "mica_license")
          and has_tag(delta.node, "crypto")
    enforce: deny
    explain: CPI.LICENSE.MISSING_PRIMITIVE.MICA,
             jurisdiction_id = delta.jurisdiction
    patch: mica_license_patch()
  }
}
```
