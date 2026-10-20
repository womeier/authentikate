(* Specialize the upstream correctness theorems to our JWT configuration. *)
From Authentikate Require Import Bytes Base64.
From Base64 Require Import Alphabet MetaRocqString.
From Base64 Require ByteString.

Theorem decode_encode (s : bytes) : decode (encode s) = Some s.
Proof. apply ByteString.decode_encode; [apply url_wf | exact I]. Qed.

Theorem encode_decode (s t : bytes) : decode s = Some t -> encode t = s.
Proof. apply ByteString.encode_decode. apply url_wf. Qed.
