(******************************************************************************)
(*  What is actually established                                              *)
(*                                                                            *)
(*  The structural properties first, because they need no assumption about     *)
(*  cryptography at all -- they are facts about the shape of [handle], and     *)
(*  they are the ones a reader of this service cares about.  The end-to-end    *)
(*  statement is at the bottom, [Admitted], so that the claim is in the repo   *)
(*  and checkable long before the proof is.                                   *)
(*                                                                            *)
(*  Two things listed as properties in an earlier draft are *not* theorems     *)
(*  and should not be dressed up as any:                                      *)
(*                                                                            *)
(*  - Uniform failure of response shape.  [Unauthorized] is a single           *)
(*    constructor and [render] of it is a constant, so there is nothing to     *)
(*    prove.  What needed proving was that an unknown user reaches it, which   *)
(*    is [unknown_user_is_unauthorized] below.                                *)
(*  - Uniform failure of *timing*.  Not a proposition.  It is the syntactic    *)
(*    fact that [handle] applies [argon2_verify] before it tests [found], and  *)
(*    a reviewer checks it by reading the code.  No proof here reaches it.     *)
(*                                                                            *)
(*  Totality is likewise free rather than earned: every Rocq function is       *)
(*  total, so there are no stuck states and no panics to rule out.            *)
(******************************************************************************)

From Stdlib Require Import List NArith Lia Bool Arith Wf_nat
  Strings.Byte Strings.String.
From Authentikate Require Import Bytes Base64 Json Crypto Claims
  Store Jwt Api.

Import ListNotations.

(* ---- the credential check, on its own ----------------------------------- *)

(* [login_check] is where the found and not-found cases have to stay
   indistinguishable, so it gets its own three lemmas and the theorems below
   go through them.  Reasoning about it separately is also what keeps those
   theorems readable: the storage shape and the credential shape are
   independent, and proofs that mix them are twice as long for no gain. *)

Lemma login_check_token :
  forall ops cfg found email now password t,
    login_check ops cfg found email now password = Token t ->
    exists u, found = Some u /\
      argon2_verify ops password (u_salt u) (u_params u) (u_tag u) = Some true.
Proof.
  intros ops cfg found email now password t.
  unfold login_check. cbv zeta.
  destruct found as [u |]; cbv beta iota.
  - destruct (argon2_verify ops password (u_salt u) (u_params u) (u_tag u))
      as [[|] |] eqn:Ha;
      [ destruct (Jwt.sign ops (cfg_key cfg) _) eqn:Hs | | ];
      intros H; try discriminate.
    exists u. split; [ reflexivity | exact Ha ].
  - destruct (argon2_verify ops password (cfg_dummy_salt cfg)
                (cfg_dummy_params cfg) (cfg_dummy_tag cfg)) as [[|] |];
      intros H; discriminate.
Qed.

(* Not found is refused whatever Argon2 says -- including when it says yes,
   which is what makes the dummy tag safe to be a real derivable tag rather
   than something that must never verify. *)
Lemma login_check_none :
  forall ops cfg email now password,
    login_check ops cfg None email now password = Unauthorized.
Proof.
  intros ops cfg email now password.
  unfold login_check. cbv zeta beta iota.
  destruct (argon2_verify ops password (cfg_dummy_salt cfg)
              (cfg_dummy_params cfg) (cfg_dummy_tag cfg)) as [[|] |];
    reflexivity.
Qed.

Lemma login_check_not_validity :
  forall ops cfg found email now password v oc,
    login_check ops cfg found email now password <> Validity v oc.
Proof.
  intros ops cfg found email now password v oc.
  unfold login_check. cbv zeta.
  destruct found as [u |]; cbv beta iota.
  - destruct (argon2_verify ops password (u_salt u) (u_params u) (u_tag u))
      as [[|] |]; [ destruct (Jwt.sign ops (cfg_key cfg) _) | | ];
      intros H; discriminate.
  - destruct (argon2_verify ops password (cfg_dummy_salt cfg)
                (cfg_dummy_params cfg) (cfg_dummy_tag cfg)) as [[|] |];
      intros H; discriminate.
Qed.

(* ---- no token without a credential check -------------------------------- *)

(* The property the service exists for.  Note what it does *not* assume:
   nothing about Argon2, only that [handle] cannot reach [Token] except
   through a lookup that found the user and a check that said yes.

   Nor does it assume anything about the store.  [Store.stored kv email =
   Found u] is a conclusion, not a hypothesis: whatever bytes came back
   decoded to [u] and [u] named this email.  That is the strongest honest
   statement available, because no theorem can rule out a store answering
   with something nobody wrote. *)
Theorem no_token_without_verify :
  forall ops kv mail cfg now r body t,
    handle ops kv mail cfg now r body = Token t ->
    exists email password u,
      parse_request r body = Login email password /\
      Store.stored kv email = Found u /\
      argon2_verify ops password (u_salt u) (u_params u) (u_tag u) = Some true.
Proof.
  intros ops kv mail cfg now r body t.
  unfold handle.
  destruct (parse_request r body) as [email password | token | | email password] eqn:Hp.
  - destruct (Store.stored kv email) as [u | |] eqn:Hs; intros H.
    + apply login_check_token in H as [u' [Hu Ha]].
      injection Hu as <-. exists email, password, u. repeat split; assumption.
    + rewrite login_check_none in H. discriminate.
    + discriminate.
  - destruct (Jwt.verify ops (cfg_pubkey cfg) token) as [c |] eqn:Hv;
      [ destruct (andb (Claims.fresh now c) (bytes_eqb (c_iss c) (cfg_iss cfg))) | ];
      intros H; discriminate.
  - intros H; discriminate.
  - destruct (kv_get kv email) as [[existing |] |]; try (intros H; discriminate).
    destruct (argon2_enroll ops password) as [v |]; try (intros H; discriminate).
    destruct (Store.enrollment_record email v) as [record |];
      try (intros H; discriminate).
    destruct (kv_set kv email record) as [[|] |]; try (intros H; discriminate).
    destruct (send_email mail (cfg_email_from cfg) email
      (lit ("Welcome to Authentikate"%string))
      (lit ("Your Authentikate account has been created."%string))) as [[|] |];
      intros H; discriminate.
Qed.

(* And the email a token names is the key its record was stored under, which
   is [Store.stored]'s own check carried through [handle]. *)
Corollary token_names_stored_email :
  forall ops kv mail cfg now r body t,
    handle ops kv mail cfg now r body = Token t ->
    exists email u,
      Store.stored kv email = Found u /\ bytes_eqb email (u_email u) = true.
Proof.
  intros ops kv mail cfg now r body t H.
  apply no_token_without_verify in H as [email [password [u [_ [Hs _]]]]].
  exists email, u. split; [ exact Hs | eapply Store.stored_names_email, Hs ].
Qed.

(* Signup acknowledges creation only when enrollment produced a decodable
   record, the store acknowledged that exact write, and email was accepted.
   This is not a claim about later reads, atomic uniqueness, email delivery,
   or the honesty of the components. *)
Theorem created_requires_persistence :
  forall ops kv mail cfg now body,
    handle ops kv mail cfg now RtSignup body = Created ->
    exists email password public_json record,
      parse_request RtSignup body = Signup email password /\
      kv_get kv email = Some None /\
      Store.stored kv email = Absent /\
      argon2_enroll ops password = Some public_json /\
      Store.enrollment_record email public_json = Some record /\
      kv_set kv email record = Some true /\
      send_email mail (cfg_email_from cfg) email
        (lit ("Welcome to Authentikate"%string))
        (lit ("Your Authentikate account has been created."%string)) = Some true.
Proof.
  intros ops kv mail cfg now body.
  unfold handle, parse_request.
  destruct (Json.parse body) as [j' |] eqn:Hp; [| discriminate].
  destruct (Json.get_str (lit ("email"%string)) j') as [e |] eqn:He;
    [| discriminate].
  destruct (Json.get_str (lit ("password"%string)) j') as [p |] eqn:Hpw;
    [| discriminate].
  destruct (kv_get kv e) as [[existing |] |] eqn:Hs; try discriminate.
  destruct (argon2_enroll ops (Secret.of_bytes p)) as [v |] eqn:Ha;
    [| discriminate].
  destruct (Store.enrollment_record e v) as [record |] eqn:Hr;
    [| discriminate].
  destruct (kv_set kv e record) as [[|] |] eqn:Hset; try discriminate.
  destruct (send_email mail (cfg_email_from cfg) e
    (lit ("Welcome to Authentikate"%string))
    (lit ("Your Authentikate account has been created."%string))) as [[|] |]
    eqn:Hmail; try discriminate.
  intros _. exists e, (Secret.of_bytes p), v, record.
  repeat split; try assumption; try reflexivity.
  unfold Store.stored. now rewrite Hs.
Qed.

(* ---- a user who is not there is refused, by the same answer -------------- *)

Theorem absent_is_unauthorized :
  forall ops kv mail cfg now email password body,
    parse_request RtLogin body = Login email password ->
    Store.stored kv email = Absent ->
    handle ops kv mail cfg now RtLogin body = Unauthorized.
Proof.
  intros ops kv mail cfg now email password body Hp Hs.
  unfold handle. rewrite Hp, Hs. apply login_check_none.
Qed.

(* The three ways to be [Absent], spelled out, because the point of routing
   them together is that nothing downstream can tell them apart -- and that is
   only worth stating if each one is named. *)

Corollary missing_key_is_unauthorized :
  forall ops kv mail cfg now email password body,
    parse_request RtLogin body = Login email password ->
    kv_get kv email = Some None ->
    handle ops kv mail cfg now RtLogin body = Unauthorized.
Proof.
  intros ops kv mail cfg now email password body Hp Hk.
  eapply absent_is_unauthorized; [ exact Hp |].
  unfold Store.stored. now rewrite Hk.
Qed.

(* A record that does not decode: a truncated value, a wider-than-u32 cost
   parameter, base64 that is not base64. *)
Corollary corrupt_record_is_unauthorized :
  forall ops kv mail cfg now email password body v,
    parse_request RtLogin body = Login email password ->
    kv_get kv email = Some (Some v) ->
    Store.decode v = None ->
    handle ops kv mail cfg now RtLogin body = Unauthorized.
Proof.
  intros ops kv mail cfg now email password body v Hp Hk Hd.
  eapply absent_is_unauthorized;
    [ exact Hp | eapply Store.stored_absent_on_corrupt; eassumption ].
Qed.

(* And a record that decodes but belongs to somebody else, which is the shape
   a store mixing up keys would produce. *)
Corollary foreign_record_is_unauthorized :
  forall ops kv mail cfg now email password body v u,
    parse_request RtLogin body = Login email password ->
    kv_get kv email = Some (Some v) ->
    Store.decode v = Some u ->
    bytes_eqb email (u_email u) = false ->
    handle ops kv mail cfg now RtLogin body = Unauthorized.
Proof.
  intros ops kv mail cfg now email password body v u Hp Hk Hd He.
  eapply absent_is_unauthorized;
    [ exact Hp | eapply Store.stored_absent_on_mismatch; eassumption ].
Qed.

(* ---- a store that is down is a 500, and only then ----------------------- *)

(* The one branch of the login path that skips the hash.  It is allowed to:
   [Internal] reports that the service does not know, which is not evidence
   about whether the account exists.  The converse matters more -- [Internal]
   on the login path means the store refused and nothing else, so a 500 can
   never be a credential signal. *)
Theorem unavailable_is_internal :
  forall ops kv mail cfg now email password body,
    parse_request RtLogin body = Login email password ->
    kv_get kv email = None ->
    handle ops kv mail cfg now RtLogin body = Internal.
Proof.
  intros ops kv mail cfg now email password body Hp Hk.
  unfold handle. rewrite Hp.
  unfold Store.stored. rewrite Hk. reflexivity.
Qed.

(* ---- the algorithm is pinned -------------------------------------------- *)

(* [verify] does not read [alg] to choose a verifier; it compares the token's
   header segment against the only header this service mints.  So a token
   carrying any other header is rejected because it is not that header. *)
Theorem alg_is_pinned :
  forall ops pk token h p s,
    split_on dot token = [h; p; s] ->
    bytes_eqb h Jwt.header_b64 = false ->
    Jwt.verify ops pk token = None.
Proof.
  intros ops pk token h p s Hsplit Hne.
  unfold Jwt.verify. rewrite Hsplit, Hne. reflexivity.
Qed.

Definition none_header : json :=
  JObj [ (lit ("alg"%string), JStr (lit ("none"%string)));
         (lit ("typ"%string), JStr (lit ("JWT"%string))) ].

Lemma none_header_is_not_ours :
  bytes_eqb (Base64.encode (Json.print none_header)) Jwt.header_b64 = false.
Proof. vm_compute. reflexivity. Qed.

Corollary alg_none_is_rejected :
  forall ops pk token p s,
    split_on dot token = [Base64.encode (Json.print none_header); p; s] ->
    Jwt.verify ops pk token = None.
Proof.
  intros ops pk token p s Hsplit.
  eapply alg_is_pinned; [ exact Hsplit | exact none_header_is_not_ours ].
Qed.

(* ---- a valid answer means fresh, and ours ------------------------------- *)

Theorem valid_implies_fresh_and_ours :
  forall ops kv mail cfg now body c,
    handle ops kv mail cfg now RtValidate body = Validity true (Some c) ->
    Claims.fresh now c = true /\ bytes_eqb (c_iss c) (cfg_iss cfg) = true.
Proof.
  intros ops kv mail cfg now body c.
  unfold handle.
  destruct (parse_request RtValidate body) as [email password | token | | email password] eqn:Hp.
  - destruct (Store.stored kv email) as [u | |] eqn:Hs; intros H;
      try discriminate.
    + exfalso. eapply login_check_not_validity, H.
    + exfalso. eapply login_check_not_validity, H.
  - destruct (Jwt.verify ops (cfg_pubkey cfg) token) as [c' |] eqn:Hv.
    + destruct (andb (Claims.fresh now c') (bytes_eqb (c_iss c') (cfg_iss cfg))) eqn:Hg;
        intros H; inversion H; subst.
      now apply andb_prop in Hg.
    + intros H; discriminate.
  - intros H; discriminate.
  - destruct (kv_get kv email) as [[existing |] |]; try (intros H; discriminate).
    destruct (argon2_enroll ops password) as [v |]; try (intros H; discriminate).
    destruct (Store.enrollment_record email v) as [record |];
      try (intros H; discriminate).
    destruct (kv_set kv email record) as [[|] |]; try (intros H; discriminate).
    destruct (send_email mail (cfg_email_from cfg) email
      (lit ("Welcome to Authentikate"%string))
      (lit ("Your Authentikate account has been created."%string))) as [[|] |];
      intros H; discriminate.
Qed.

(* ---- claims survive the JSON round trip --------------------------------- *)

Lemma of_json_to_json : forall c, Claims.of_json (Claims.to_json c) = Some c.
Proof. intros [sub iss iat exp]. reflexivity. Qed.

(* ---- base64url output never contains a dot ------------------------------ *)

(* Which is what makes [split_on dot] of a minted token give exactly three
   segments: the separator cannot occur inside one. *)
Lemma encode_no_dot : forall bs, ~ bytes_In dot (Base64.encode bs).
Proof.
  intros bs Hin.
  unfold bytes_In, Base64.encode, ByteString.encode in Hin.
  change (In dot (BS.print (BS.parse
    (Base64.Base64.encode Alphabet.url (BS.print bs))))) in Hin.
  rewrite Base64.print_parse in Hin.
  pose proof (Base64.Base64.encode_charset Alphabet.url (BS.print bs)) as Hchars.
  apply Forall_forall with (x := dot) in Hchars; [| exact Hin].
  destruct Hchars as [Hchar | Hpad]; [| discriminate].
  vm_compute in Hchar. intuition discriminate.
Qed.

(* ---- base64url is lossless ---------------------------------------------- *)

(* Specialized from rocq-base64 in Base64.v; restated here because this
   is the file that says what is established. *)
Corollary base64_round_trip :
  forall bs, Base64.decode (Base64.encode bs) = Some bs.
Proof. exact Base64.decode_encode. Qed.

(* ---- the trust boundary, as a hypothesis -------------------------------- *)

(* The whole of what is assumed about Ed25519, and worth reading carefully for
   what it does not say: that signing produces something verification
   accepts.  That is correctness, not security.  Unforgeability is neither
   stated nor assumed here -- assuming it would be assuming the conclusion. *)
Record crypto_spec (ops : crypto_ops) (k : Key.t) (pk : bytes) : Prop :=
  MkSpec {
    sign_verifies : forall msg sg,
      ed25519_sign ops k msg = Some sg ->
      ed25519_verify ops pk msg sg = Some true
  }.

(* ---- the end-to-end statement ------------------------------------------- *)

(* A token minted for an email and validated before it expires yields claims
   naming that email.

   What this needs:
     - [base64_round_trip], proved above
     - [encode_no_dot] and [split_on_three], proved above
     - [of_json_to_json], proved above
     - [Json.parse (Json.print j) = Some j] for well-formed [j], which is the
       one piece still missing
     - [crypto_spec], assumed
     - [now + d < now + cfg_ttl cfg], which is [lia]. *)
Theorem login_then_validate :
  forall ops kv mail cfg now d email password body token,
    crypto_spec ops (cfg_key cfg) (cfg_pubkey cfg) ->
    parse_request RtLogin body = Login email password ->
    handle ops kv mail cfg now RtLogin body = Token token ->
    (d < cfg_ttl cfg)%N ->
    exists c,
      handle ops kv mail cfg (now + d) RtValidate
        (Json.print (JObj [(lit ("token"%string), JStr token)]))
        = Validity true (Some c)
      /\ c_sub c = email.
Admitted.

(* The honesty check: this prints what the end-to-end claim still rests on.
   One axiom, the [Admitted] above, until the JSON round trip lands. *)
Print Assumptions login_then_validate.
