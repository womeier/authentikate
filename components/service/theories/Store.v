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
(*  one-way: this module cannot serialize a [Secret.t].  Enrollment instead    *)
(*  receives explicitly public JSON from the Argon2 component.                 *)
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
  kv_get : bytes -> option (option bytes);
  (* key, value -> this caller created the pair.  [Some true] is "the key was
     absent and now holds this value, and no other caller can be told the
     same"; [Some false] is "the key was already taken"; [None] is the store
     refusing.  The caller must inspect the result, so extraction cannot
     erase a unit-valued write.

     Create, not set.  There is no overwrite operation in this record, which
     is the reason the service cannot replace an account's record even by
     mistake: the primitive does not exist.  A rehash-on-login migration
     would have to add one, deliberately.

     What this record cannot say is that the operation is atomic -- a record
     of functions has no notion of two callers.  The hypotheses in Proofs.v
     say it instead, and the adapter earns them with a compare-and-swap. *)
  kv_create : bytes -> bytes -> option bool
}.

(* ---- the stored record -------------------------------------------------- *)

(* Binary fields are base64url, the same encoding the tokens use, so there is
   one encoding in the system and it is the one with a proved round trip.
   JSON because the parser is already here and already strict: a duplicate key
   or a backslash in a stored record is a rejection, not an interpretation. *)

Definition fits_u32 (n : N) : bool := N.ltb n 4294967296.

(* The public half of an enrollment: what the Argon2 component returns, and
   nothing besides.  Split out of [of_json] because the component does not
   know the email, and because [enrollment_record] below builds the record it
   writes out of these fields rather than out of the component's own JSON.
   Salt and tag stay base64 here -- this is the record as read, before any
   decoding. *)
Record public_record := MkPublic {
  pr_salt64 : bytes;
  pr_tag64 : bytes;
  pr_params : argon2_params
}.

Definition public_of_json (j : json) : option public_record :=
  match Json.get_str (lit ("salt"%string)) j,
        Json.get_str (lit ("tag"%string)) j,
        Json.get_num (lit ("algorithm"%string)) j,
        Json.get_num (lit ("memory_kib"%string)) j,
        Json.get_num (lit ("iterations"%string)) j,
        Json.get_num (lit ("parallelism"%string)) j,
        Json.get_num (lit ("tag_length"%string)) j with
  | Some salt64, Some tag64, Some alg, Some mem, Some iter, Some par, Some len =>
      (* The five knobs are [u32] in the WIT, so a record naming a wider one
         would be truncated on the way through the canonical ABI.  Reject it
         rather than hash with parameters nobody wrote down. *)
      if andb (andb (andb (fits_u32 alg) (fits_u32 mem))
                    (andb (fits_u32 iter) (fits_u32 par)))
              (fits_u32 len)
      then Some (MkPublic salt64 tag64 (MkParams alg mem iter par len))
      else None
  | _, _, _, _, _, _, _ => None
  end.

Definition of_json (j : json) : option user :=
  match Json.get_str (lit ("email"%string)) j, public_of_json j with
  | Some email, Some p =>
      match Base64.decode (pr_salt64 p), Base64.decode (pr_tag64 p) with
      | Some salt, Some tag =>
          Some (MkUser email salt (pr_params p) (Secret.of_bytes tag))
      | _, _ => None
      end
  | _, _ => None
  end.

Definition decode (v : bytes) : option user :=
  match Json.parse v with
  | Some j => of_json j
  | None => None
  end.

(* Enrollment supplies salt, tag and all five cost fields, but does not know
   the email.  The record is printed here, from the fields this module read
   out of the component's JSON -- not the component's JSON with an email
   prepended, which is what this used to be.  The difference is what a
   provider can put into storage: nothing but these eight fields, no nested
   objects and no numbers wider than a [u32].  It is also what makes the
   record's shape something this module can reason about, which the signup
   lifecycle proof in Proofs.v needs: a record with a field the printer and
   parser do not round trip cannot be read back in a proof.

   A provider that names an email at all is refused rather than overridden.
   That used to happen by accident -- the prepended key collided with the
   provider's and [Json.parse] rejects duplicates -- and is now a test the
   code makes. *)
Definition record_json (email : bytes) (p : public_record) : json :=
  JObj [ (lit ("email"%string), JStr email);
         (lit ("salt"%string), JStr (pr_salt64 p));
         (lit ("tag"%string), JStr (pr_tag64 p));
         (lit ("algorithm"%string), JNum (ap_algorithm (pr_params p)));
         (lit ("memory_kib"%string), JNum (ap_memory_kib (pr_params p)));
         (lit ("iterations"%string), JNum (ap_iterations (pr_params p)));
         (lit ("parallelism"%string), JNum (ap_parallelism (pr_params p)));
         (lit ("tag_length"%string), JNum (ap_tag_length (pr_params p))) ].

Definition enrollment_record (email public_json : bytes) : option bytes :=
  match Json.parse public_json with
  | Some j =>
      match Json.get (lit ("email"%string)) j, public_of_json j with
      | None, Some p =>
          let v := Json.print (record_json email p) in
          (* Written only if it reads back: the write path does not store what
             the read path would refuse.  The base64 fields are decoded for
             the first time here. *)
          match decode v with
          | Some _ => Some v
          | None => None
          end
      | _, _ => None
      end
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
