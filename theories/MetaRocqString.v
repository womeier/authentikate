(* Copied from rocq-base64/metarocq/MetaRocqString.v at
   b0f629e5b1170d8015b30c44323b6bc220dd9613.
   Copyright (c) 2026 Wolfgang Meier. MIT License; see LICENSE. *)

(** * The MetaRocq bytestring instance

    Base64 operations and their correctness proofs are provided by [ByteString].
    This module supplies the byte conversions and relates the generic length
    result to MetaRocq's native length.

    This bridge is kept out of the installed [rocq-base64] package so that
    depending on it does not pull in MetaRocq; it is built and tested only in
    CI, from this directory. See [metarocq/Tests.v]. *)

From Stdlib Require Import Strings.Byte Lists.List Arith.PeanoNat.
From MetaRocq.Utils Require bytestring.
From Base64 Require Import Alphabet.
From Base64 Require ByteString.
Import ListNotations.

(** MetaRocq's [String] module would otherwise shadow the standard library's. *)
Module BS := MetaRocq.Utils.bytestring.String.

Lemma print_parse (l : list byte) : BS.print (BS.parse l) = l.
Proof. induction l as [|b l IH]; cbn; congruence. Qed.

Lemma parse_print (s : BS.t) : BS.parse (BS.print s) = s.
Proof. apply BS.print_parse_inv. Qed.

Lemma print_append (s t : BS.t) :
  BS.print (BS.append s t) = BS.print s ++ BS.print t.
Proof. induction s as [|b s IH]; cbn; congruence. Qed.

Lemma print_length (s : BS.t) : length (BS.print s) = BS.length s.
Proof. induction s as [|b s IH]; cbn; congruence. Qed.

#[export] Instance metarocq_bytestring : ByteString.ByteString BS.t := {
  ByteString.to_bytes := BS.print;
  ByteString.of_bytes := BS.parse;
  ByteString.fits _ := True;
  ByteString.of_to_bytes := parse_print;
  ByteString.to_of_bytes bs _ := print_parse bs;
  ByteString.fits_to_bytes _ := I;
  ByteString.fits_shorter _ _ _ _ := I
}.

Theorem bytestring_encode_length c (s : BS.t) :
  BS.length (ByteString.encode c s) =
  if pad c then 4 * ((BS.length s + 2) / 3)
  else 4 * (BS.length s / 3) + match BS.length s mod 3 with
                               | 0 => 0
                               | 1 => 2
                               | _ => 3
                               end.
Proof.
  rewrite <- !print_length.
  exact (@ByteString.encode_length BS.t metarocq_bytestring c s I).
Qed.

(** The generic [append] matches MetaRocq's own bytestring concatenation. *)
Lemma append_bytestring s t : ByteString.append s t = BS.append s t.
Proof.
  change (BS.parse (BS.print s ++ BS.print t) = BS.append s t).
  rewrite <- print_append. apply parse_print.
Qed.
