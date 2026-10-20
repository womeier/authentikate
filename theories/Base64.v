(* JWTs and stored account fields use strict, unpadded base64url.
   Use rocq-base64's MetaRocq bytestring instance directly. *)
From Authentikate Require Import Bytes.
From Base64 Require Import Alphabet MetaRocqString.
From Base64 Require Strings.

Definition encode (s : bytes) : bytes := Strings.encode url s.
Definition decode (s : bytes) : option bytes := Strings.decode url s.
