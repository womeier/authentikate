(******************************************************************************)
(*  Byte strings                                                              *)
(*                                                                            *)
(*  Requests and responses are bytes, and so is everything a JWT is made of,  *)
(*  so this is the bottom layer: a byte string is a [list byte], and what is  *)
(*  here is the arithmetic the encodings on top of it need.                   *)
(******************************************************************************)

From Stdlib Require Import List Lia PeanoNat Strings.Byte.
Import ListNotations.

Definition bytes := list byte.

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
