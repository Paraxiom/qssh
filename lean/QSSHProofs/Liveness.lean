/-
  QSSHProofs.Liveness

  Liveness of the qssh-node forward-tunnel reconnect loop.

  Background (issue #1):
    `qssh-node` runs an outer "auto-reconnect" loop that wraps an inner
    `run_forward_loop` doing `transport.receive_message().await`. The
    inner await is only allowed to return on (a) clean Disconnect, or
    (b) a transport `Err`. Without any keepalive — neither socket-level
    nor protocol-level — a silently half-open TCP path produces neither:
    the await blocks forever, the outer reconnect machinery never runs,
    the process stays `active` per systemd, the tunnel is dead.

  The fix sets `SO_KEEPALIVE` with finite probe parameters (idle 30 s,
  interval 10 s, retries 3) so the kernel eventually surfaces an error.

  This file gives a small operational model and a liveness theorem:
  given a finite keepalive deadline, the inner loop terminates within
  bounded time on a dead path. That's the necessary condition for the
  outer reconnect to ever fire.

  Mirrors: src/client.rs `apply_tcp_keepalive` + `run_forward_loop`.
-/

import Mathlib.Tactic.NormNum

namespace QSSHProofs.Liveness

/-! ## Operational model -/

/-- Inputs derived from the socket configuration. -/
structure KeepaliveCfg where
  idleSecs    : Nat  -- TCP_KEEPIDLE  (production: 30)
  intervalSecs: Nat  -- TCP_KEEPINTVL (production: 10)
  retries     : Nat  -- TCP_KEEPCNT   (production:  3)
  deriving DecidableEq, Repr

/-- Outcome of an inner `run_forward_loop` instance on a dead path. -/
inductive InnerOutcome
  | HangsForever                  -- no keepalive: pre-fix behavior
  | Errors  (afterSecs : Nat)     -- transport returns Err after a bound
  deriving DecidableEq, Repr

/-- The kernel's keepalive timeline: once `idleSecs` of silence have
    elapsed, the kernel sends up to `retries+1` probes, one every
    `intervalSecs`. The connection is declared dead after the last
    unanswered probe. This is the Linux TCP keepalive semantics. -/
def kernelDeadlineSecs (k : KeepaliveCfg) : Nat :=
  k.idleSecs + k.intervalSecs * (k.retries + 1)

/-- Production configuration as wired in `apply_tcp_keepalive`. -/
def prodCfg : KeepaliveCfg :=
  { idleSecs := 30, intervalSecs := 10, retries := 3 }

/-- The forward loop's behavior on a dead path, as a function of the
    socket's keepalive configuration. A keepalive of *all zeros* means
    `SO_KEEPALIVE` was effectively disabled; the production case is
    nonzero and produces a finite deadline. -/
def innerLoopOnDeadPath (k : KeepaliveCfg) : InnerOutcome :=
  if k.idleSecs = 0 ∧ k.intervalSecs = 0 ∧ k.retries = 0 then
    InnerOutcome.HangsForever
  else
    InnerOutcome.Errors (kernelDeadlineSecs k)

/-! ## Concrete deadline -/

/-- The production deadline is exactly 70 s: 30 + 10·(3+1). -/
theorem prod_deadline_eq_70 : kernelDeadlineSecs prodCfg = 70 := by
  unfold kernelDeadlineSecs prodCfg
  rfl

/-- The production-configured forward loop terminates with a transport
    error after a finite, kernel-bounded delay on a dead path. -/
theorem prod_terminates_on_dead_path :
    innerLoopOnDeadPath prodCfg = InnerOutcome.Errors 70 := by
  unfold innerLoopOnDeadPath
  -- prodCfg has nonzero idle, so the `if` falls through to `Errors`.
  simp [prodCfg]
  -- The `Errors` argument is the kernel deadline = 70.
  exact prod_deadline_eq_70

/-! ## Liveness theorem -/

/-- **Main liveness theorem.** For *any* keepalive configuration with a
    nonzero idle time, the inner forward loop terminates with an error
    on a dead path within a finite, computable bound. This is the
    necessary condition for `qssh-node`'s outer auto-reconnect loop to
    actually run on silent path failures (issue #1). -/
theorem keepalive_implies_liveness (k : KeepaliveCfg) (h : k.idleSecs > 0) :
    ∃ bound : Nat, innerLoopOnDeadPath k = InnerOutcome.Errors bound := by
  refine ⟨kernelDeadlineSecs k, ?_⟩
  unfold innerLoopOnDeadPath
  -- `k.idleSecs > 0` rules out the zero-zero-zero branch.
  have : ¬ (k.idleSecs = 0 ∧ k.intervalSecs = 0 ∧ k.retries = 0) := by
    intro ⟨h0, _, _⟩
    exact Nat.lt_irrefl 0 (h0 ▸ h)
  simp [this]

/-- **Corollary — the pre-fix (no keepalive) regime has no liveness.**
    With `SO_KEEPALIVE` unset, the loop hangs forever; no finite bound
    exists. This is exactly the production bug documented in issue #1. -/
theorem no_keepalive_no_liveness :
    innerLoopOnDeadPath ⟨0, 0, 0⟩ = InnerOutcome.HangsForever := by
  unfold innerLoopOnDeadPath
  simp

end QSSHProofs.Liveness
