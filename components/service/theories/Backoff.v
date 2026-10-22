(******************************************************************************)
(*  Exponential backoff, as a policy                                          *)
(*                                                                            *)
(*  The state is two numbers -- how many failures in a row, and the time       *)
(*  before which the next attempt is refused -- and the policy is three total  *)
(*  functions over them.  Nothing here reads a store or a clock; [now] is an   *)
(*  argument, as it is everywhere else in this development.                   *)
(*                                                                            *)
(*  The theorem at the bottom is the one worth having.  It is not about a      *)
(*  single request: it bounds the number of password guesses an attacker can   *)
(*  make in a window of time, by induction over a trace of attempts.  Two      *)
(*  regimes, and the second is the one that governs in practice:               *)
(*                                                                            *)
(*    below the cap   guesses grow like log2(T / base)                        *)
(*    above the cap   guesses grow like T / cap                               *)
(*                                                                            *)
(*  So [bo_cap] -- not [bo_base] -- sets the long-run guess rate.  Doubling    *)
(*  is only the transient.  A deployment that tunes the base and leaves the    *)
(*  cap at a minute has chosen one guess per minute, forever.                 *)
(*                                                                            *)
(*  NOT WIRED INTO [Api.handle], and deliberately.  Three things have to be    *)
(*  settled first, and two of them are adversarial to properties already       *)
(*  proved:                                                                    *)
(*                                                                            *)
(*  1. What the counter is keyed on.  Keyed on the email, a distinguishable    *)
(*     "too many requests" is a user-enumeration oracle -- a far better one    *)
(*     than the timing channel rule 3 of PLAN.md closes, because it is a       *)
(*     status code rather than a microsecond.  Preserving rule 3 means         *)
(*     counters for emails that do not exist, which is an attacker-driven      *)
(*     unbounded write.  Keyed on the client address there is no per-account   *)
(*     leak, but the address comes from the host, outside the perimeter.       *)
(*  2. Lockout.  Backoff keyed on the email lets anyone who knows an address   *)
(*     hold its owner out indefinitely by failing logins.  A cap bounds the    *)
(*     damage per attempt; it does not stop a loop.                           *)
(*  3. The clock becomes security-critical.  Today [now] only has to be        *)
(*     honest enough for [exp]; a host that passes a large [now] shortens a    *)
(*     token's life, which is safe in the conservative direction.  Under       *)
(*     backoff the same host bypasses throttling entirely.  Monotone,          *)
(*     truthful timestamps join [crypto_spec] in the assumption set.           *)
(*                                                                            *)
(*  And one that is mechanical rather than a judgement: the read-modify-write  *)
(*  below has to be atomic or the bound is vacuous -- n concurrent requests    *)
(*  all read the same count and all proceed. This needs a new atomic counter   *)
(*  capability; the accounts interface deliberately exposes no such operation. *)
(******************************************************************************)

From Stdlib Require Import List NArith Lia ZArith.

Import ListNotations.
Local Open Scope N_scope.

Record bo_config := MkBoConfig {
  bo_base : N;   (* the delay after the first failure *)
  bo_cap : N     (* ceiling on a single delay *)
}.

Record backoff := MkBackoff {
  bo_count : N;  (* consecutive failures *)
  bo_until : N   (* no attempt is served before this *)
}.

(* Capped, which is what makes the policy usable and also what weakens the
   theorem below from logarithmic to linear.  Both halves are proved, so the
   trade is visible rather than assumed. *)
Definition delay (cfg : bo_config) (n : N) : N :=
  N.min (bo_cap cfg) (bo_base cfg * 2 ^ n).

Definition throttled (now : N) (b : backoff) : bool := N.ltb now (bo_until b).

Definition on_failure (cfg : bo_config) (now : N) (b : backoff) : backoff :=
  MkBackoff (bo_count b + 1) (now + delay cfg (bo_count b)).

(* A success clears the record.  Which is the right policy and also the reason
   the theorem below is stated over traces of *failures*: an attacker who
   guesses correctly has already won, so bounding their guesses after that
   point is not interesting. *)
Definition on_success (b : backoff) : backoff := MkBackoff 0 0.

(* ---- the delay is what it says ------------------------------------------ *)

Lemma min_cap_double : forall cap x, 2 * x <= cap -> N.min cap (2 * x) = 2 * N.min cap x.
Proof. intros cap x H. lia. Qed.

Lemma delay_mono : forall cfg n m, n <= m -> delay cfg n <= delay cfg m.
Proof.
  intros cfg n m Hnm. unfold delay.
  assert (2 ^ n <= 2 ^ m) by (apply N.pow_le_mono_r; lia).
  assert (bo_base cfg * 2 ^ n <= bo_base cfg * 2 ^ m) by (apply N.mul_le_mono_l; lia).
  lia.
Qed.

Lemma delay_exact : forall cfg n,
  bo_base cfg * 2 ^ n <= bo_cap cfg -> delay cfg n = bo_base cfg * 2 ^ n.
Proof. intros cfg n H. unfold delay. lia. Qed.

(* The "exponential" in the name, for as long as the cap allows it. *)
Lemma delay_doubles : forall cfg n,
  bo_base cfg * 2 ^ (n + 1) <= bo_cap cfg ->
  delay cfg (n + 1) = 2 * delay cfg n.
Proof.
  intros cfg n H.
  assert (E : bo_base cfg * 2 ^ (n + 1) = 2 * (bo_base cfg * 2 ^ n)).
  { rewrite N.pow_add_r. change (2 ^ 1) with 2. ring. }
  unfold delay. rewrite E. rewrite E in H. now apply min_cap_double.
Qed.

(* And the other regime: once the cap binds it stays bound, because the
   uncapped delay only grows. *)
Lemma delay_capped : forall cfg n,
  bo_cap cfg <= bo_base cfg * 2 ^ n -> delay cfg n = bo_cap cfg.
Proof. intros cfg n H. unfold delay. lia. Qed.

Lemma cap_binds_up : forall cfg n m,
  n <= m -> bo_cap cfg <= bo_base cfg * 2 ^ n -> bo_cap cfg <= bo_base cfg * 2 ^ m.
Proof.
  intros cfg n m Hnm H.
  assert (2 ^ n <= 2 ^ m) by (apply N.pow_le_mono_r; lia).
  assert (bo_base cfg * 2 ^ n <= bo_base cfg * 2 ^ m) by (apply N.mul_le_mono_l; lia).
  lia.
Qed.

(* ---- a trace of attempts ------------------------------------------------ *)

(* [failures cfg b ts] counts how many of the attempts at times [ts] actually
   reach the credential check, starting from state [b] and all of them wrong.
   Throttled attempts are skipped: they cost the attacker no guess, and they
   cost us no Argon2 either, which is the other half of why backoff is worth
   having.

   The timestamps are not required to be sorted.  They do not need to be --
   an out-of-order trace is a *weaker* hypothesis, so the bound holds for a
   host whose clock jitters, as long as it does not run backwards past
   [bo_until]. *)
Fixpoint failures (cfg : bo_config) (b : backoff) (ts : list N) : nat :=
  match ts with
  | [] => 0
  | t :: ts' =>
      if throttled t b
      then failures cfg b ts'
      else S (failures cfg (on_failure cfg t b) ts')
  end.

(* The time that [n] further guesses must consume, starting from a counter
   standing at [c].  The sum of the next [n] delays. *)
Fixpoint reserve (cfg : bo_config) (c : N) (n : nat) : N :=
  match n with
  | O => 0
  | S m => delay cfg c + reserve cfg (c + 1) m
  end.

(* The whole content, in one induction.  Everything below is this lemma with
   [reserve] computed in one regime or the other. *)
Lemma failures_le : forall ts cfg b n horizon,
  Forall (fun t => t < horizon) ts ->
  horizon <= bo_until b + reserve cfg (bo_count b) n ->
  (failures cfg b ts <= n)%nat.
Proof.
  induction ts as [| t ts IH]; intros cfg b n horizon Hh Hb.
  - cbn. lia.
  - (* [Forall_inv] hands back the predicate unapplied, as a beta-redex that
       the arithmetic tactics do not see through. *)
    assert (Ht := Forall_inv Hh). cbv beta in Ht.
    assert (Hts := Forall_inv_tail Hh).
    cbn [failures].
    destruct (throttled t b) eqn:Hthr.
    + eapply IH; eassumption.
    + unfold throttled in Hthr. apply N.ltb_ge in Hthr.
      destruct n as [| m].
      * (* No budget left, so the attempt had to be throttled: [horizon] is at
           or below [bo_until b], and [t] is below [horizon]. *)
        cbn in Hb. lia.
      * cbn [reserve] in Hb.
        assert (IHm : (failures cfg (on_failure cfg t b) ts <= m)%nat).
        { eapply IH; [ exact Hts | ]. unfold on_failure. cbn. lia. }
        lia.
Qed.

(* ---- the two regimes ---------------------------------------------------- *)

(* Stated as a sum rather than with a subtraction, which is not cosmetic: [N]
   subtracts by truncation, so [2 ^ n - 1] is a term every arithmetic tactic
   has to case-split on.  Adding [bo_base * 2 ^ c] to both sides instead keeps
   the whole development subtraction-free and the proofs are [ring]
   identities.  The familiar closed form is this one rearranged:
   [reserve cfg 0 n = bo_base * (2 ^ n - 1)]. *)
Lemma reserve_exact : forall n cfg c,
  bo_base cfg * 2 ^ (c + N.of_nat n) <= bo_cap cfg ->
  reserve cfg c n + bo_base cfg * 2 ^ c = bo_base cfg * 2 ^ (c + N.of_nat n).
Proof.
  induction n as [| m IH]; intros cfg c H.
  - cbn. rewrite N.add_0_r. ring.
  - rewrite Nat2N.inj_succ, <- N.add_1_l in *.
    assert (Hc : bo_base cfg * 2 ^ c <= bo_cap cfg).
    { apply N.le_trans with (bo_base cfg * 2 ^ (c + (1 + N.of_nat m)));
        [| exact H ].
      apply N.mul_le_mono_l, N.pow_le_mono_r; lia. }
    assert (HI : reserve cfg (c + 1) m + bo_base cfg * 2 ^ (c + 1)
                 = bo_base cfg * 2 ^ (c + 1 + N.of_nat m)).
    { apply IH. replace (c + 1 + N.of_nat m) with (c + (1 + N.of_nat m)) by lia.
      exact H. }
    (* Put every power in terms of [2 ^ c] and [2 ^ m] by hand.  [rewrite !]
       does not reach the [2 ^ (c + 1)] that rewriting the larger exponent
       creates, so the three equations are spelled out. *)
    assert (E1 : 2 ^ (c + 1) = 2 ^ c * 2).
    { rewrite N.pow_add_r. change (2 ^ 1) with 2. reflexivity. }
    assert (E2 : 2 ^ (c + 1 + N.of_nat m) = 2 ^ c * 2 * 2 ^ N.of_nat m).
    { rewrite !N.pow_add_r. change (2 ^ 1) with 2. reflexivity. }
    assert (E3 : 2 ^ (c + (1 + N.of_nat m)) = 2 ^ c * (2 * 2 ^ N.of_nat m)).
    { rewrite !N.pow_add_r. change (2 ^ 1) with 2. reflexivity. }
    rewrite E1, E2 in HI. rewrite E3.
    cbn [reserve]. rewrite delay_exact by exact Hc.
    set (B := bo_base cfg) in *.
    set (X := 2 ^ c) in *.
    set (P := 2 ^ N.of_nat m) in *.
    set (R := reserve cfg (c + 1) m) in *.
    (* [ring] rather than an arithmetic solver: the identity is nonlinear in
       three unknowns, and the induction hypothesis supplies the one step
       that is not pure algebra. *)
    replace (B * (X * (2 * P))) with (B * (X * 2 * P)) by ring.
    rewrite <- HI. ring.
Qed.

Lemma reserve_capped : forall n cfg c,
  bo_cap cfg <= bo_base cfg * 2 ^ c ->
  reserve cfg c n = N.of_nat n * bo_cap cfg.
Proof.
  induction n as [| m IH]; intros cfg c H.
  - reflexivity.
  - cbn [reserve]. rewrite delay_capped by exact H.
    rewrite IH by (eapply cap_binds_up; [| exact H ]; lia).
    rewrite Nat2N.inj_succ. lia.
Qed.

(* ---- the theorems ------------------------------------------------------- *)

(* A clean account at [t0]: nothing held against it, and not throttled there
   ([throttled t0 (MkBackoff 0 t0)] is [t0 < t0], which is false).  This is
   the attacker's best case, which is the case a bound has to be stated in. *)
Definition clean (t0 : N) : backoff := MkBackoff 0 t0.

(* Below the cap: guesses are logarithmic in the window.
   Read it the other way round, which is how it gets used -- to allow [n]
   guesses an attacker must own the account's address for
   [bo_base * (2^n - 1)]: 1023 * base for ten guesses, about 10^6 * base for
   twenty. *)
Theorem guesses_are_logarithmic : forall cfg n t0 T ts,
  bo_base cfg * 2 ^ N.of_nat n <= bo_cap cfg ->
  T + bo_base cfg <= bo_base cfg * 2 ^ N.of_nat n ->
  Forall (fun t => t < t0 + T) ts ->
  (failures cfg (clean t0) ts <= n)%nat.
Proof.
  intros cfg n t0 T ts Hcap HT Hh.
  eapply failures_le; [ exact Hh | ].
  assert (HR := reserve_exact n cfg 0).
  rewrite N.add_0_l in HR. specialize (HR Hcap).
  change (2 ^ 0) with 1 in HR.
  unfold clean. cbn.
  set (B := bo_base cfg) in *.
  set (Q := B * 2 ^ N.of_nat n) in *.
  lia.
Qed.

(* Above the cap: linear, and this is the regime a real deployment lives in,
   because the point of a cap is that the counter reaches it.  The honest
   reading of the pair is that exponential backoff buys a sharp transient and
   then settles into a fixed rate of one guess per [bo_cap].

   The window opens at [t0] and the counter's own clock is required to be no
   earlier -- [bo_until b = t0] is the sharp case, which is exactly what
   [clean t0] gives the theorem above.  That direction is load-bearing rather
   than convenient: a counter whose [bo_until] lies in the past has a free
   guess banked, and the bound would be [n + 1]. *)
Theorem guesses_are_linear_past_cap : forall cfg n t0 T ts b,
  bo_cap cfg <= bo_base cfg * 2 ^ bo_count b ->
  t0 <= bo_until b ->
  T <= N.of_nat n * bo_cap cfg ->
  Forall (fun t => t < t0 + T) ts ->
  (failures cfg b ts <= n)%nat.
Proof.
  intros cfg n t0 T ts b Hcap Hu HT Hh.
  eapply failures_le; [ exact Hh | ].
  rewrite reserve_capped by exact Hcap. lia.
Qed.

(* The degenerate case is worth naming even though it needs no proof: with
   [bo_base = 0] and [bo_cap = 0] every delay is zero, [bo_until] never moves,
   nothing is ever throttled, and both theorems above hold vacuously -- their
   hypotheses force [T = 0] and [n] is unconstrained.  So [bo_base = 0] is not
   "backoff switched off", it is "the bounds say nothing".  A deployment that
   wants it off should say so in the host and not by zeroing the config. *)
