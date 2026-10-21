(* JWTs and stored account fields use strict, unpadded base64url.
   Use the local copy of rocq-base64's MetaRocq bytestring instance. *)
From Authentikate Require Import Bytes MetaRocqString.
From Base64 Require Import Alphabet.
From Base64 Require ByteString.

Definition encode (s : bytes) : bytes := ByteString.encode url_unpadded s.
Definition decode (s : bytes) : option bytes := ByteString.decode url_unpadded s.
