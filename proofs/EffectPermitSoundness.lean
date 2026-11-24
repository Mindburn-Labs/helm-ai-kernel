/- This model proves ceiling precedence for an abstract decision function.
   The Go kernel tests exercise the implementation of that contract. -/

namespace HelmOSS.Soundness

/-- The three-valued verdict returned by every policy front-end. -/
inductive Verdict
  | allow
  | deny
  | escalate
  deriving DecidableEq, Repr

/-- Both policy layers receive the same request. -/
structure Request where
  /-- Symbolic action label. -/
  action : String
  deriving Repr

/-- A P0 ceiling: pure Boolean predicate on requests. -/
def Ceiling : Type := Request → Bool

/-- A P1 bundle models the verdict of a policy for a request. -/
def Bundle : Type := Request → Verdict

/-- Evaluate the bundle only when the ceiling permits the request. -/
def Decide (c : Ceiling) (b : Bundle) (r : Request) : Verdict :=
  if c r then b r else Verdict.deny

/-- An allow verdict requires the ceiling to permit the request. -/
theorem ceiling_precedence
    (c : Ceiling) (b : Bundle) (r : Request)
    (h : Decide c b r = Verdict.allow) :
    c r = true := by
  unfold Decide at h
  by_cases hc : c r
  · exact hc
  · simp [hc] at h

/-- A ceiling denial rules out an allow verdict. -/
theorem ceiling_deny_blocks_allow
    (c : Ceiling) (b : Bundle) (r : Request)
    (hc : c r = false) :
    Decide c b r ≠ Verdict.allow := by
  intro hAllow
  have : c r = true := ceiling_precedence c b r hAllow
  rw [hc] at this
  exact Bool.false_ne_true this

/-- A request permitted by both layers receives an allow verdict. -/
theorem decide_passthrough_on_allow
    (c : Ceiling) (b : Bundle) (r : Request)
    (hc : c r = true) (hb : b r = Verdict.allow) :
    Decide c b r = Verdict.allow := by
  unfold Decide
  simp [hc, hb]

/-- A ceiling denial forces a deny verdict. -/
theorem decide_deny_on_ceiling_deny
    (c : Ceiling) (b : Bundle) (r : Request)
    (hc : c r = false) :
    Decide c b r = Verdict.deny := by
  unfold Decide
  simp [hc]

end HelmOSS.Soundness
