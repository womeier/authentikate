(* Copyright (c) 2026 Wolfgang Meier. MIT License; see LICENSE. *)

(* Strict, unpadded base64url for JWTs and stored account fields. *)
From Authentikate Require Import Bytes.
From Base64 Require Import Alphabet.
From Base64 Require ByteString.
(* The [ByteString] instance for MetaRocq's byte strings, which is what makes
   the generic operations below run on [bytes].  It lives in rocq-base64's own
   rocq-base64-bytestring package -- the bridge is kept there so that nothing
   about it has to be restated here. *)
From Base64.MetaRocq Require Export InstanceBytestring.

Definition encode (s : bytes) : bytes := ByteString.encode url_unpadded s.
Definition decode (s : bytes) : option bytes := ByteString.decode url_unpadded s.

Theorem decode_encode (s : bytes) : decode (encode s) = Some s.
Proof. apply ByteString.decode_encode; [apply url_unpadded_wf | exact I]. Qed.

Theorem encode_decode (s t : bytes) : decode s = Some t -> encode t = s.
Proof. apply ByteString.encode_decode. apply url_unpadded_wf. Qed.
