(******************************************************************************)
(*  Byte strings                                                              *)
(*                                                                            *)
(*  Requests and responses are bytes, and so is everything a JWT is made of,  *)
(*  so this is the bottom layer: a MetaRocq byte string, and what is           *)
(*  here is the arithmetic the encodings on top of it need.                   *)
(******************************************************************************)

From Stdlib Require Import List Lia PeanoNat NArith Strings.Byte Strings.String.
From MetaRocq.Utils Require bytestring.
Import ListNotations.

Module BS := MetaRocq.Utils.bytestring.String.
Definition bytes := BS.t.

Definition bytes_rev (s : bytes) : bytes := BS.rev BS.EmptyString s.
Definition bytes_In (b : byte) (s : bytes) : Prop := In b (BS.print s).
Definition bytes_Forall (P : byte -> Prop) (s : bytes) : Prop :=
  Forall P (BS.print s).

Lemma bytes_append_assoc (a b c : bytes) :
  BS.append a (BS.append b c) = BS.append (BS.append a b) c.
Proof. induction a; cbn; congruence. Qed.

Lemma bytes_append_empty (s : bytes) : BS.append s BS.EmptyString = s.
Proof. induction s; cbn; congruence. Qed.

Lemma bytes_length_append (a b : bytes) :
  BS.length (BS.append a b) = (BS.length a + BS.length b)%nat.
Proof. induction a; cbn; congruence. Qed.

Lemma bytes_append_eq_empty (a b : bytes) :
  BS.append a b = BS.EmptyString -> a = BS.EmptyString /\ b = BS.EmptyString.
Proof. destruct a; cbn; intros H; [auto | discriminate]. Qed.

Lemma bytes_rev_acc (s acc : bytes) :
  BS.rev acc s = BS.append (bytes_rev s) acc.
Proof.
  assert (H : forall s a b,
    BS.rev (BS.append a b) s = BS.append (BS.rev a s) b).
  { induction s0 as [| c s0 IH]; intros a b; cbn; [reflexivity |].
    exact (IH (BS.String c a) b). }
  exact (H s BS.EmptyString acc).
Qed.

Lemma bytes_rev_cons (b : byte) (s : bytes) :
  bytes_rev (BS.String b s) =
  BS.append (bytes_rev s) (BS.String b BS.EmptyString).
Proof. unfold bytes_rev at 1. cbn. apply bytes_rev_acc. Qed.

Lemma bytes_print_append (a b : bytes) :
  BS.print (BS.append a b) = BS.print a ++ BS.print b.
Proof. induction a; cbn; congruence. Qed.

Lemma bytes_print_length (s : bytes) : List.length (BS.print s) = BS.length s.
Proof. induction s; cbn; congruence. Qed.

Lemma bytes_Forall_forall (P : byte -> Prop) (s : bytes) :
  bytes_Forall P s <-> forall b, bytes_In b s -> P b.
Proof. unfold bytes_Forall, bytes_In. apply Forall_forall. Qed.

Lemma bytes_In_append (b : byte) (s t : bytes) :
  bytes_In b (BS.append s t) <-> bytes_In b s \/ bytes_In b t.
Proof. unfold bytes_In. rewrite bytes_print_append. apply in_app_iff. Qed.

(* Byte and nat, in both directions.  The stdlib's [Byte.of_nat] is partial;
   the encodings want a total function, and they only ever feed it values
   they have already reduced mod 256. *)
Definition byte_of_nat (n : nat) : byte :=
  match Byte.of_nat (Nat.modulo n 256) with
  | Some b => b
  | None => x00  (* unreachable: the modulo is in range *)
  end.

Definition nat_of_byte (b : byte) : nat := Byte.to_nat b.

Lemma nat_of_byte_of_nat (n : nat) :
  n < 256 -> nat_of_byte (byte_of_nat n) = n.
Proof.
  intros Hn.
  unfold byte_of_nat, nat_of_byte.
  rewrite Nat.mod_small by exact Hn.
  destruct (Byte.of_nat n) eqn:E.
  - now apply Byte.to_of_nat in E.
  - exfalso. apply Byte.of_nat_None_iff in E. lia.
Qed.

Lemma byte_of_nat_of_byte (b : byte) : byte_of_nat (nat_of_byte b) = b.
Proof.
  unfold byte_of_nat, nat_of_byte.
  rewrite Nat.mod_small by (pose proof (Byte.to_nat_bounded b); lia).
  now rewrite Byte.of_to_nat.
Qed.

(* Byte and [N].  The encodings do their arithmetic in [N] rather than [nat]:
   CertiCoq represents [nat] in unary, so a timestamp as a [nat] is a heap
   cell per second since 1970. *)
Definition byte_of_N (n : N) : byte :=
  match Byte.of_N (N.modulo n 256) with
  | Some b => b
  | None => x00  (* unreachable: the modulo is in range *)
  end.

Definition N_of_byte (b : byte) : N := Byte.to_N b.

(* Literals.  [lit "alg"] is how a constant appears in the encodings; writing
   it out with [BS.String] constructors would be unreadable. *)
Definition lit (s : string) : bytes := BS.of_string s.

Fixpoint bytes_eqb (a b : bytes) : bool :=
  match a, b with
  | BS.EmptyString, BS.EmptyString => true
  | BS.String x a', BS.String y b' => if Byte.eqb x y then bytes_eqb a' b' else false
  | _, _ => false
  end.

(* Equality on [bytes] short-circuits at the first differing byte, so it is
   only ever applied to public values here -- JSON keys, a token's header, an
   email.  Comparing a tag or a signature with it would be a timing oracle;
   that comparison belongs in the Rust component.  See PLAN.md. *)

Definition dot : byte := "."%byte.

(* Split on a separator, keeping empty fields, so that [split_on] of a compact
   JWS always has three of them (or the token is malformed). *)
Fixpoint split_on (sep : byte) (input : bytes) : list bytes :=
  match input with
  | BS.EmptyString => [BS.EmptyString]
  | BS.String b rest =>
      if Byte.eqb b sep then BS.EmptyString :: split_on sep rest
      else
        match split_on sep rest with
        | [] => [BS.String b BS.EmptyString]  (* unreachable *)
        | f :: fs => BS.String b f :: fs
        end
  end.

Fixpoint join (sep : byte) (parts : list bytes) : bytes :=
  match parts with
  | [] => BS.EmptyString
  | [p] => p
  | p :: ps => BS.append p (BS.String sep (join sep ps))
  end.

(* Decimal, for JSON numbers.  The fuel is the digit count: [N] has no
   structural recursion to offer and 32 digits is past any timestamp. *)
Fixpoint decimal_aux (fuel : nat) (n : N) (acc : bytes) : bytes :=
  match fuel with
  | O => acc  (* unreachable for the magnitudes used here *)
  | S fuel' =>
      let d := byte_of_N ((48 + N.modulo n 10)%N) in
      if N.ltb n 10 then BS.String d acc
      else decimal_aux fuel' (N.div n 10) (BS.String d acc)
  end.

Definition decimal_of_N (n : N) : bytes := decimal_aux 32 n BS.EmptyString.

Definition digit_val (b : byte) : option N :=
  let v := N_of_byte b in
  if andb (N.leb 48 v) (N.leb v 57) then Some ((v - 48)%N) else None.

Fixpoint N_of_decimal_aux (input : bytes) (acc : N) : option N :=
  match input with
  | BS.EmptyString => Some acc
  | BS.String b rest =>
      match digit_val b with
      | Some d => N_of_decimal_aux rest ((acc * 10 + d)%N)
      | None => None
      end
  end.

(* No leading-zero rule and no sign: JSON allows neither a [+] nor a [01],
   and the empty string is not a number. *)
Definition N_of_decimal (input : bytes) : option N :=
  match input with
  | BS.EmptyString => None
  | _ => N_of_decimal_aux input 0%N
  end.

Lemma N_of_byte_of_N (n : N) : (n < 256)%N -> N_of_byte (byte_of_N n) = n.
Proof.
  intros Hn.
  unfold byte_of_N, N_of_byte.
  rewrite N.mod_small by exact Hn.
  destruct (Byte.of_N n) eqn:E.
  - now apply Byte.to_of_N in E.
  - exfalso. apply Byte.of_N_None_iff in E. lia.
Qed.

Lemma N_of_byte_lt_256 (b : byte) : (N_of_byte b < 256)%N.
Proof. unfold N_of_byte. pose proof (Byte.to_N_bounded b). lia. Qed.

Lemma byte_of_N_of_byte (b : byte) : byte_of_N (N_of_byte b) = b.
Proof.
  unfold byte_of_N, N_of_byte.
  rewrite N.mod_small by (pose proof (Byte.to_N_bounded b); lia).
  now rewrite Byte.of_to_N.
Qed.

(* [byte_of_N] is already reducing mod 256, so a value carrying higher bits
   names the same byte as its low eight.  The base64 reconstruction leans on
   this: the byte it rebuilds comes out with a borrowed bit above it. *)
Lemma byte_of_N_mod (n : N) : byte_of_N (n mod 256)%N = byte_of_N n.
Proof. unfold byte_of_N. now rewrite N.Div0.mod_mod. Qed.

Lemma byte_eqb_false (a b : byte) : a <> b -> Byte.eqb a b = false.
Proof.
  intros H.
  destruct (Byte.eqb a b) eqn:E; [| reflexivity].
  apply byte_dec_bl in E. congruence.
Qed.

Lemma bytes_eqb_refl (s : bytes) : bytes_eqb s s = true.
Proof.
  induction s as [| b s IH]; [ reflexivity |].
  cbn. now rewrite (byte_dec_lb (@Logic.eq_refl byte b)), IH.
Qed.

(* Splitting at a separator that occurs nowhere else.  [split_on] is the only
   thing standing between a token and its three segments, so it is worth
   knowing exactly. *)
Lemma split_on_absent (sep : byte) (s : bytes) :
  ~ bytes_In sep s -> split_on sep s = [s].
Proof.
  induction s as [| b s' IH]; intros Hn; [reflexivity |].
  cbn in Hn |- *.
  rewrite byte_eqb_false by (intro; subst; apply Hn; now left).
  rewrite IH by (intro; apply Hn; now right).
  reflexivity.
Qed.

Lemma split_on_prefix (sep : byte) (h t : bytes) :
  ~ bytes_In sep h ->
  split_on sep (BS.append h (BS.String sep t)) = h :: split_on sep t.
Proof.
  induction h as [| b h' IH]; intros Hn.
  - cbn. now rewrite (byte_dec_lb (@Logic.eq_refl byte sep)).
  - cbn in Hn |- *.
    rewrite byte_eqb_false by (intro; subst; apply Hn; now left).
    rewrite IH by (intro; apply Hn; now right).
    reflexivity.
Qed.

Lemma split_on_three (h p s : bytes) :
  ~ bytes_In dot h -> ~ bytes_In dot p -> ~ bytes_In dot s ->
  split_on dot (BS.append h (BS.String dot (BS.append p (BS.String dot s)))) = [h; p; s].
Proof.
  intros Hh Hp Hs.
  rewrite split_on_prefix by exact Hh.
  rewrite split_on_prefix by exact Hp.
  rewrite split_on_absent by exact Hs.
  reflexivity.
Qed.
