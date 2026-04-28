/-
  EffectPermitSoundness.lean

  Workstream F / F2 — Phase 3 of the helm-oss 100% SOTA execution plan.

  Machine-checked proof of the ceiling-precedence theorem for HELM's
  decision kernel: given a P0 ceiling and a P1 bundle, the kernel's
  Decide function never returns ALLOW for an action the ceiling forbids.

  The model abstracts the Go implementation as follows.

  * Verdict is the three-valued result `Verdict.allow | .deny | .escalate`
    that the policy front-ends produce. Cedar/Rego/CEL all collapse into
    this shape (see core/pkg/policybundles/{cedar,rego}/bundle.go and
    tests/conformance/policy-langs/harness.go).

  * Request is opaque at this layer. The proof does not rely on its
    internals — only on the equality of the request passed through both
    layers, which the Go kernel guarantees by construction.

  * A `Ceiling` is a Boolean predicate on Request: `true` means "this
    request is permitted under the P0 ceiling", `false` means "forbidden
    by the ceiling, no policy bundle can override".

  * A `Bundle` is a function from Request to Verdict: this is the P1
    layer. P1 bundles are signed, hot-loaded, and may return any of the
    three verdicts.

  * `Decide` composes the two layers: if the ceiling forbids the request
    the verdict is forced to DENY, otherwise the bundle's verdict is
    returned unchanged. This mirrors the Go implementation's
    short-circuit at the kernel boundary (the bundle never sees a
    ceiling-forbidden request).

  Theorem `ceiling_precedence` states: if `Decide c b r = ALLOW` then the
  ceiling permitted `r`. Equivalently — there is no request a ceiling
  forbids on which Decide can return ALLOW, regardless of what the bundle
  says. This is what the Go kernel must enforce, and the proof confirms
  the *abstract* contract holds; preserving the contract concretely in
  Go is the responsibility of the kernel test suite (see
  core/pkg/kernel/*_test.go).
-/

namespace HelmOSS.Soundness

/-- The three-valued verdict returned by every policy front-end. -/
inductive Verdict
  | allow
  | deny
  | escalate
  deriving DecidableEq, Repr

/-- A request is opaque at the soundness layer. The proof never reads
    fields of `Request`; identity through both layers is the only fact
    we rely on. -/
structure Request where
  /-- Symbolic action label; carried so `Request` is non-empty in the
      Lean kernel sense. The proof never inspects it. -/
  action : String
  deriving Repr

/-- A P0 ceiling: pure Boolean predicate on requests. -/
def Ceiling : Type := Request → Bool

/-- A P1 bundle: pure function from request to verdict. Bundles in the
    Go kernel are signed wazero artifacts; here they are abstract
    functions, which is sufficient for the soundness theorem. -/
def Bundle : Type := Request → Verdict

/-- The kernel's `Decide` function. Ceiling-precedence: a ceiling-deny
    forces Verdict.deny regardless of what the bundle returns. The Go
    kernel implements this short-circuit at the boundary; this Lean
    definition is the abstract contract. -/
def Decide (c : Ceiling) (b : Bundle) (r : Request) : Verdict :=
  if c r then b r else Verdict.deny

/-- The ceiling-precedence theorem.

    If `Decide` ever returns `ALLOW` for a request `r`, then the ceiling
    `c` permitted `r`. There is no path through `Decide` that returns
    `ALLOW` while the ceiling forbids: the `else` branch is `Verdict.deny`
    by construction. -/
theorem ceiling_precedence
    (c : Ceiling) (b : Bundle) (r : Request)
    (h : Decide c b r = Verdict.allow) :
    c r = true := by
  unfold Decide at h
  by_cases hc : c r
  · exact hc
  · -- c r = false, so the `else` branch fires and Decide = .deny.
    -- The hypothesis says it equals .allow — contradiction.
    simp [hc] at h

/-- Convenience corollary in contrapositive form: a ceiling-deny implies
    the kernel cannot return ALLOW. This is the form the prose claims
    quote in marketing copy. -/
theorem ceiling_deny_blocks_allow
    (c : Ceiling) (b : Bundle) (r : Request)
    (hc : c r = false) :
    Decide c b r ≠ Verdict.allow := by
  intro hAllow
  have : c r = true := ceiling_precedence c b r hAllow
  rw [hc] at this
  exact Bool.false_ne_true this

/-- Sanity check: a ceiling-allowing request whose bundle returns ALLOW
    yields ALLOW from `Decide`. The combined system is not a no-op. -/
theorem decide_passthrough_on_allow
    (c : Ceiling) (b : Bundle) (r : Request)
    (hc : c r = true) (hb : b r = Verdict.allow) :
    Decide c b r = Verdict.allow := by
  unfold Decide
  simp [hc, hb]

/-- Sanity check: a ceiling-deny always lands on `.deny` regardless of
    what the bundle would have returned. Pairs with
    `ceiling_deny_blocks_allow`. -/
theorem decide_deny_on_ceiling_deny
    (c : Ceiling) (b : Bundle) (r : Request)
    (hc : c r = false) :
    Decide c b r = Verdict.deny := by
  unfold Decide
  simp [hc]

end HelmOSS.Soundness
