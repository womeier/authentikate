(******************************************************************************)
(*  Where users live                                                          *)
(*                                                                            *)
(*  Not here, is the short answer: in a key-value store, under the email as    *)
(*  the key, as the JSON object [of_json] below reads.                        *)
(*                                                                            *)
(*  The store is reached through a record of operations, the same device       *)
(*  [Crypto.crypto_ops] uses and for the same reason.  A [Parameter get :      *)
(*  bytes -> option bytes] would be a *function* in Rocq's logic: two reads of *)
(*  one key would provably agree, a write would provably change nothing, and  *)
(*  every theorem downstream would rest on an axiom.  Passing the operations  *)
(*  in instead keeps Proofs.v closed under the global context and confines the *)
(*  axiom to extraction.                                                      *)
(*                                                                            *)
(*  Three outcomes, not two.  [None] is the store refusing -- unreachable,     *)
(*  timed out -- and [Some None] is the key being absent.  Collapsing them     *)
(*  would be the mistake [argon2_verify]'s [option bool] exists to avoid: a    *)
(*  failure answering as a fact.                                              *)
(*                                                                            *)
(*  The value is decoded *here* rather than by the host, which is the point of *)
(*  a blob store over SQL columns: the host moves bytes and decides nothing,   *)
(*  and the record format sits inside the verified perimeter.                 *)
(*                                                                            *)
(*  The salt is public and stored beside the tag; the tag becomes a            *)
(*  [Secret.t] on the way in.  Note what follows from that seal being          *)
(*  one-way: this module can read a record and *cannot write one*.  Minting a  *)
(*  record needs [derive], and belongs to a registration endpoint that does    *)
(*  not exist yet.                                                            *)
(******************************************************************************)

From Stdlib Require Import List NArith Strings.Byte Strings.String.
From Authentikate Require Import Bytes Base64 Json Crypto.

Import ListNotations.
Local Open Scope N_scope.

Record user := MkUser {
  u_email : bytes;
  u_salt : bytes;
  u_params : argon2_params;
  u_tag : Secret.t
}.

Record store_ops := MkStore {
  (* key -> the stored value.  [None] is the store refusing; [Some None] is
     the key being absent. *)
  kv_get : bytes -> option (option bytes)
}.

(* ---- the stored record -------------------------------------------------- *)

(* Binary fields are base64url, the same encoding the tokens use, so there is
   one encoding in the system and it is the one with a proved round trip.
   JSON because the parser is already here and already strict: a duplicate key
   or a backslash in a stored record is a rejection, not an interpretation. *)

Definition fits_u32 (n : N) : bool := N.ltb n 4294967296.

Definition of_json (j : json) : option user :=
  match Json.get_str (lit ("email"%string)) j,
        Json.get_str (lit ("salt"%string)) j,
        Json.get_str (lit ("tag"%string)) j,
        Json.get_num (lit ("algorithm"%string)) j,
        Json.get_num (lit ("memory_kib"%string)) j,
        Json.get_num (lit ("iterations"%string)) j,
        Json.get_num (lit ("parallelism"%string)) j,
        Json.get_num (lit ("tag_length"%string)) j with
  | Some email, Some salt64, Some tag64,
    Some alg, Some mem, Some iter, Some par, Some len =>
      (* The five knobs are [u32] in the WIT, so a record naming a wider one
         would be truncated on the way through the canonical ABI.  Reject it
         rather than hash with parameters nobody wrote down. *)
      if andb (andb (andb (fits_u32 alg) (fits_u32 mem))
                    (andb (fits_u32 iter) (fits_u32 par)))
              (fits_u32 len)
      then
        match Base64.decode salt64, Base64.decode tag64 with
        | Some salt, Some tag =>
            Some (MkUser email salt (MkParams alg mem iter par len)
                         (Secret.of_bytes tag))
        | _, _ => None
        end
      else None
  | _, _, _, _, _, _, _, _ => None
  end.

Definition decode (v : bytes) : option user :=
  match Json.parse v with
  | Some j => of_json j
  | None => None
  end.

(* ---- a lookup, and what can come of one --------------------------------- *)

Inductive lookup_result :=
  | Found : user -> lookup_result
  | Absent : lookup_result
  | Unavailable : lookup_result.

(* A record that does not parse, and a record belonging to someone else, are
   both [Absent] -- the same answer as a key that is not there.  That is
   deliberate: the response must not depend on whether an account exists, and
   a 500 for a corrupt record would say that it does.  The cost is
   diagnosability, since this module cannot log: a deployment that breaks the
   record format locks every user out with "wrong password" rather than with
   anything that names the real problem.  A smoke test catches it; a confused
   user does not. *)
Definition stored (kv : store_ops) (email : bytes) : lookup_result :=
  match kv_get kv email with
  | None => Unavailable
  | Some None => Absent
  | Some (Some v) =>
      match decode v with
      | Some u => if bytes_eqb email (u_email u) then Found u else Absent
      | None => Absent
      end
  end.

(* What the email test buys: whatever comes back is the record for the key
   that was asked for.  A store that answers with another user's record --
   or a host that fetches the wrong key -- cannot log anyone in. *)
Lemma stored_names_email :
  forall kv email u, stored kv email = Found u -> bytes_eqb email (u_email u) = true.
Proof.
  intros kv email u H. unfold stored in H.
  destruct (kv_get kv email) as [[v |] |]; try discriminate.
  destruct (decode v) as [u' |]; try discriminate.
  destruct (bytes_eqb email (u_email u')) eqn:E; try discriminate.
  now injection H as <-.
Qed.

Lemma stored_absent_on_corrupt :
  forall kv email v,
    kv_get kv email = Some (Some v) -> decode v = None -> stored kv email = Absent.
Proof. intros kv email v Hk Hd. unfold stored. now rewrite Hk, Hd. Qed.

Lemma stored_absent_on_mismatch :
  forall kv email v u,
    kv_get kv email = Some (Some v) -> decode v = Some u ->
    bytes_eqb email (u_email u) = false -> stored kv email = Absent.
Proof. intros kv email v u Hk Hd He. unfold stored. now rewrite Hk, Hd, He. Qed.
