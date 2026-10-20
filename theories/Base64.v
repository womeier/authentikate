(* JWTs and stored account fields use strict, unpadded base64url.
   Use rocq-base64's MetaRocq bytestring instance directly. *)
From Authentikate Require Import Bytes.
From Base64 Require Import Alphabet MetaRocqString.
From Base64 Require ByteString.

Definition encode (s : bytes) : bytes := ByteString.encode url s.
Definition decode (s : bytes) : option bytes := ByteString.decode url s.
