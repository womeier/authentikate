(******************************************************************************)
(*  The trust boundary                                                        *)
(*                                                                            *)
(*  The cryptographic operations the service needs, as a record of             *)
(*  functions rather than as axioms.  Three reasons:                           *)
(*                                                                            *)
(*  - The pure service can compile and be tested without foreign primitives.   *)
(*  - It turns trust into hypotheses.  A theorem that needs the signature      *)
(*    scheme to work says so in its statement, which is a stronger and more    *)
(*    honest thing than an [Axiom] nobody rereads.                            *)
(*  - [option] in every result forces the caller to handle a component that    *)
(*    answered [error] rather than to assume it cannot.                       *)
(*                                                                            *)
(*  The record is instantiated once, in [extraction.v], with the registered    *)
(*  primitives that the two adapters in [crypto/] realise.                     *)
(******************************************************************************)

From Stdlib Require Import List NArith Strings.Byte.
From Authentikate Require Import Bytes.

Import ListNotations.

(* Secrets.  [t] is sealed: outside this module there is no eliminator, no
   equality and no way back to [bytes], so the code above *cannot* branch on a
   secret or compare one.  That is the constant-time discipline made
   structural -- checked by the type checker rather than by reading the code.
   CertiCoq erases the module, so it costs nothing at runtime.

   See PLAN.md: extracted Rocq cannot be constant-time, so the guarantee has
   to be that secrets are only ever moved, never inspected. *)
Module Type SECRET.
  Parameter t : Set.
  Parameter of_bytes : bytes -> t.
End SECRET.

Module Secret : SECRET.
  Definition t := bytes.
  Definition of_bytes (b : bytes) : t := b.
End Secret.

(* The signing key, as an opaque handle rather than as its bytes.  The key
   lives in the ed25519 component; this side holds only a reference to it, so
   a disclosure bug in the Rocq module -- or the host reading its linear
   memory, which it can trivially do -- cannot leak it.

   [of_handle] exists for the instantiation boundary alone.  Nothing in the
   service calls it. *)
Module Type KEY.
  Parameter t : Set.
  Parameter of_handle : N -> t.
End KEY.

Module Key : KEY.
  Definition t := N.
  Definition of_handle (n : N) : t := n.
End Key.

(* Argon2's cost knobs, mirroring the [params] record and the [algorithm] enum
   in crypto/wit/argon2.wit.  Public, all of them: how expensive a hash was is
   not a secret, and it cannot be one -- it is stored beside the tag, because a
   tag is only verifiable under the parameters it was derived with.

   Which is why these are an argument and not a constant.  Compiling them into
   the adapter, as it does today, binds every stored tag to whatever
   [recommended-params] returned the day it was written; the next time that
   recommendation moves, every stored tag stops verifying at once.

   Bounded to u32 by [Store.of_json], which is what the canonical ABI wants. *)
Record argon2_params := MkParams {
  ap_algorithm : N;      (* 0 argon2d, 1 argon2i, 2 argon2id *)
  ap_memory_kib : N;
  ap_iterations : N;
  ap_parallelism : N;
  ap_tag_length : N
}.

Record crypto_ops := MkOps {
  (* password, salt, cost parameters, expected tag.  The comparison happens
     inside the component, in constant time; the tag never comes back here. *)
  argon2_verify : Secret.t -> bytes -> argon2_params -> Secret.t -> option bool;
  (* A fresh random salt is generated inside the Argon2 component.  The result
     is PUBLIC JSON with base64url salt/tag and numeric algorithm/cost fields;
     Store.enrollment_record adds the email.  No secret eliminator is exposed. *)
  argon2_enroll : Secret.t -> option bytes;
  (* key handle, message *)
  ed25519_sign : Key.t -> bytes -> option bytes;
  (* public key, message, signature.  All three are public. *)
  ed25519_verify : bytes -> bytes -> bytes -> option bool
}.
