(******************************************************************************)
(*  What is actually established                                              *)
(*                                                                            *)
(*  The structural properties first, because they need no assumption about     *)
(*  cryptography at all -- they are facts about the shape of [handle], and     *)
(*  they are the ones a reader of this service cares about.  The end-to-end   *)
(*  statement is at the bottom, and proved: what it rests on besides          *)
(*  [crypto_spec] is two conditions on the configuration the host installs    *)
(*  -- a printable issuer and a bounded expiry -- stated as hypotheses        *)
(*  because neither is a property of [handle].  It is a correctness result    *)
(*  and not a security one; see the note above [crypto_spec].                 *)
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
From Authentikate Require Import Bytes Base64 Json JsonProofs Crypto Claims
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

(* ---- base64url output is printable ASCII -------------------------------- *)

(* [encode_no_dot] above is one byte's worth of this.  The general fact is
   what a token needs: every byte base64url produces is printable and is
   neither a quote nor a backslash, so a token can travel inside the JSON
   object [validate] takes without escaping -- which the printer could not do
   for it. *)
Lemma encode_ok_byte : forall bs b,
  bytes_In b (Base64.encode bs) -> ok_byteb b = true.
Proof.
  intros bs b Hin.
  unfold bytes_In, Base64.encode, ByteString.encode in Hin.
  change (In b (BS.print (BS.parse
    (Base64.Base64.encode Alphabet.url (BS.print bs))))) in Hin.
  rewrite Base64.print_parse in Hin.
  pose proof (Base64.Base64.encode_charset Alphabet.url (BS.print bs)) as Hchars.
  apply Forall_forall with (x := b) in Hchars; [| exact Hin].
  destruct Hchars as [Hchar | Hpad].
  - vm_compute in Hchar.
    repeat (destruct Hchar as [<- | Hchar]; [ reflexivity |]). contradiction.
  - subst. reflexivity.
Qed.

Lemma ok_string_encode : forall bs, ok_string (Base64.encode bs).
Proof.
  intros bs. apply ok_string_pointwise. intros b. apply encode_ok_byte.
Qed.

Lemma ok_byteb_dot : ok_byteb dot = true.
Proof. reflexivity. Qed.

Lemma ok_string_header_b64 : ok_string Jwt.header_b64.
Proof. unfold Jwt.header_b64. apply ok_string_encode. Qed.

(* Stated over three variables rather than inlined into the token, and it has
   to be: [Jwt.header_b64] is a closed term, so a unifier allowed to look
   inside [BS.append] evaluates the whole base64 encoding of the header and
   then matches against the resulting byte chain.  Opaque arguments keep the
   append first-order. *)
Lemma ok_string_dotted : forall a b c,
  ok_string a -> ok_string b -> ok_string c ->
  ok_string (BS.append (BS.append a (BS.String dot b)) (BS.String dot c)).
Proof.
  intros a b c Ha Hb Hc.
  apply ok_string_append.
  - apply ok_string_append;
      [ exact Ha | apply ok_string_String; [ exact ok_byteb_dot | exact Hb ] ].
  - apply ok_string_String; [ exact ok_byteb_dot | exact Hc ].
Qed.

(* So a minted token is a printable string: three base64url segments and the
   two dots between them. *)
Lemma sign_ok_string : forall ops k c t,
  Jwt.sign ops k c = Some t -> ok_string t.
Proof.
  intros ops k c t H. unfold Jwt.sign in H. cbv zeta in H.
  destruct (ed25519_sign ops k (Jwt.signing_input Jwt.header_b64
    (Base64.encode (Json.print (Claims.to_json c))))) as [sg |] eqn:Es;
    [| discriminate].
  (* [injection] would hand back the token with the header's base64 evaluated,
     which is the same blowup again.  Writing the equation out keeps the term
     folded; conversion accepts the two spellings. *)
  assert (E : t = BS.append (Jwt.signing_input Jwt.header_b64
    (Base64.encode (Json.print (Claims.to_json c))))
    (BS.String dot (Base64.encode sg)))
    by (injection H as E'; symmetry; exact E').
  rewrite E. unfold Jwt.signing_input.
  apply ok_string_dotted;
    [ exact ok_string_header_b64 | apply ok_string_encode | apply ok_string_encode ].
Qed.

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

(* ---- the pieces of the end-to-end statement ----------------------------- *)

(* The email a login was asked for is safe to serialize.  This is where the
   parser's soundness is spent: [ok_string] on a string that came out of a
   request body is what rules out an email closing one claim and opening
   another. *)
Lemma login_email_ok : forall body email password,
  parse_request RtLogin body = Login email password -> ok_string email.
Proof.
  intros body email password H. unfold parse_request in H.
  destruct (Json.parse body) as [j |] eqn:Ej; [| discriminate].
  destruct (Json.get_str (lit ("email"%string)) j) as [e |] eqn:Ee;
    [| discriminate].
  destruct (Json.get_str (lit ("password"%string)) j) as [pw |] eqn:Epw;
    [| discriminate].
  injection H as E1 E2. rewrite <- E1.
  eapply parse_get_str_ok; [ exact Ej | exact Ee ].
Qed.

(* [login_check_token] says a token implies a verified credential; this says
   which token it is. *)
Lemma login_check_token_sign :
  forall ops cfg found email now password t,
    login_check ops cfg found email now password = Token t ->
    Jwt.sign ops (cfg_key cfg)
      (MkClaims email (cfg_iss cfg) now (now + cfg_ttl cfg)) = Some t.
Proof.
  intros ops cfg found email now password t.
  unfold login_check. cbv zeta.
  destruct found as [u |]; cbv beta iota.
  - destruct (argon2_verify ops password (u_salt u) (u_params u) (u_tag u))
      as [[|] |] eqn:Ha;
      [ destruct (Jwt.sign ops (cfg_key cfg) _) as [t' |] eqn:Hs | | ];
      intros H; try discriminate.
    injection H as E. now rewrite <- E.
  - destruct (argon2_verify ops password (cfg_dummy_salt cfg)
                (cfg_dummy_params cfg) (cfg_dummy_tag cfg)) as [[|] |];
      intros H; discriminate.
Qed.

Lemma login_token_sign :
  forall ops kv mail cfg now body email password token,
    parse_request RtLogin body = Login email password ->
    handle ops kv mail cfg now RtLogin body = Token token ->
    Jwt.sign ops (cfg_key cfg)
      (MkClaims email (cfg_iss cfg) now (now + cfg_ttl cfg)) = Some token.
Proof.
  intros ops kv mail cfg now body email password token Hp Ht.
  unfold handle in Ht. rewrite Hp in Ht.
  destruct (Store.stored kv email) as [u | |].
  - eapply login_check_token_sign. exact Ht.
  - rewrite login_check_none in Ht. discriminate.
  - discriminate.
Qed.

(* The token's three segments, recovered.  [Jwt.sign] appends the signature to
   the signing input, so the dots end up associated the other way from what
   [split_on_three] wants. *)
Lemma split_sign_shape : forall h p s,
  ~ bytes_In dot h -> ~ bytes_In dot p -> ~ bytes_In dot s ->
  split_on dot (BS.append (BS.append h (BS.String dot p)) (BS.String dot s))
    = [h; p; s].
Proof.
  intros h p s Hh Hp Hs.
  rewrite <- bytes_append_assoc. cbn [BS.append].
  now apply split_on_three.
Qed.

(* Claims survive printing.  The four conditions [parse_print_obj] asks for,
   discharged: the keys are literals, the strings come from the parser and the
   configuration, and the two timestamps are bounded. *)
Lemma claims_round_trip : forall c,
  ok_string (c_sub c) -> ok_string (c_iss c) ->
  (c_iat c < 10 ^ 32)%N -> (c_exp c < 10 ^ 32)%N ->
  Json.parse (Json.print (Claims.to_json c)) = Some (Claims.to_json c).
Proof.
  intros [sub iss iat exp] Hsub Hiss Hiat Hexp.
  cbn [c_sub c_iss c_iat c_exp] in Hsub, Hiss, Hiat, Hexp.
  unfold Claims.to_json. cbn [c_sub c_iss c_iat c_exp].
  apply parse_print_obj.
  - cbn [Datatypes.length]. lia.
  - apply Forall_cons; [ split; [ ok_literal | exact Hsub ] |].
    apply Forall_cons; [ split; [ ok_literal | exact Hiss ] |].
    apply Forall_cons; [ split; [ ok_literal | exact Hiat ] |].
    apply Forall_cons; [ split; [ ok_literal | exact Hexp ] |].
    apply Forall_nil.
  - cbn. repeat split; (reflexivity || exact I).
Qed.

(* Verification, over opaque segments.  Stated this way for the same reason as
   [ok_string_dotted]: [Jwt.header_b64] is closed, and a unifier allowed
   inside it computes the header's base64 instead of matching. *)
Lemma verify_parts : forall ops pk h p s sg c,
  bytes_eqb h Jwt.header_b64 = true ->
  ~ bytes_In dot h -> ~ bytes_In dot p -> ~ bytes_In dot s ->
  Base64.decode s = Some sg ->
  ed25519_verify ops pk (BS.append h (BS.String dot p)) sg = Some true ->
  Base64.decode p = Some (Json.print (Claims.to_json c)) ->
  Json.parse (Json.print (Claims.to_json c)) = Some (Claims.to_json c) ->
  Jwt.verify ops pk
    (BS.append (BS.append h (BS.String dot p)) (BS.String dot s)) = Some c.
Proof.
  intros ops pk h p s sg c Hh Hdh Hdp Hds Hs Hv Hp Hrt.
  unfold Jwt.verify, Jwt.signing_input.
  rewrite split_sign_shape by assumption.
  cbv beta iota. rewrite Hh. cbv beta iota.
  rewrite Hs. cbv beta iota.
  rewrite Hv. cbv beta iota.
  rewrite Hp. cbv beta iota.
  rewrite Hrt. cbv beta iota.
  apply of_json_to_json.
Qed.

(* A minted token verifies, and yields the claims it was minted from. *)
Lemma verify_sign : forall ops cfg c t,
  crypto_spec ops (cfg_key cfg) (cfg_pubkey cfg) ->
  Json.parse (Json.print (Claims.to_json c)) = Some (Claims.to_json c) ->
  Jwt.sign ops (cfg_key cfg) c = Some t ->
  Jwt.verify ops (cfg_pubkey cfg) t = Some c.
Proof.
  intros ops cfg c t Hspec Hrt H.
  unfold Jwt.sign in H. cbv zeta in H.
  destruct (ed25519_sign ops (cfg_key cfg) (Jwt.signing_input Jwt.header_b64
    (Base64.encode (Json.print (Claims.to_json c))))) as [sg |] eqn:Es;
    [| discriminate].
  assert (E : t = BS.append (Jwt.signing_input Jwt.header_b64
    (Base64.encode (Json.print (Claims.to_json c))))
    (BS.String dot (Base64.encode sg)))
    by (injection H as E'; symmetry; exact E').
  rewrite E. unfold Jwt.signing_input.
  eapply verify_parts.
  - apply bytes_eqb_refl.
  - apply encode_no_dot.
  - apply encode_no_dot.
  - apply encode_no_dot.
  - apply base64_round_trip.
  - apply (sign_verifies ops (cfg_key cfg) (cfg_pubkey cfg) Hspec).
    unfold Jwt.signing_input in Es. exact Es.
  - apply base64_round_trip.
  - exact Hrt.
Qed.

(* The request body [validate] is handed, parsed back.  A token is printable
   ASCII, so the one-field object it travels in round trips. *)
Lemma parse_token_request : forall token,
  ok_string token ->
  parse_request RtValidate
    (Json.print (JObj [(lit ("token"%string), JStr token)])) = Validate token.
Proof.
  intros token Hok. unfold parse_request.
  rewrite parse_print_obj.
  - reflexivity.
  - cbn [Datatypes.length]. lia.
  - apply Forall_cons; [ split; [ ok_literal | exact Hok ] |]. apply Forall_nil.
  - cbn. repeat split; (reflexivity || exact I).
Qed.

(* ---- the end-to-end statement ------------------------------------------- *)

(* A token minted for an email and validated before it expires yields claims
   naming that email.

   Two hypotheses are not provable and so are stated.  The issuer has to be a
   printable ASCII string, because the printer does not escape, and
   [now + cfg_ttl cfg] has to fit in 32 decimal digits, because the numeral
   round trip is bounded.  Both are the host's to satisfy when it installs the
   configuration; neither is a property of [handle].

   What this rests on besides them:
     - [login_email_ok], so the email prints back
     - [claims_round_trip], the JSON round trip applied to a claim set
     - [verify_sign]: [base64_round_trip], [encode_no_dot], [split_on_three]
       and [of_json_to_json]
     - [crypto_spec], assumed: signing produces a verifiable signature
     - [d < cfg_ttl cfg], which is [lia]. *)
Theorem login_then_validate :
  forall ops kv mail cfg now d email password body token,
    crypto_spec ops (cfg_key cfg) (cfg_pubkey cfg) ->
    ok_string (cfg_iss cfg) ->
    (now + cfg_ttl cfg < 10 ^ 32)%N ->
    parse_request RtLogin body = Login email password ->
    handle ops kv mail cfg now RtLogin body = Token token ->
    (d < cfg_ttl cfg)%N ->
    exists c,
      handle ops kv mail cfg (now + d) RtValidate
        (Json.print (JObj [(lit ("token"%string), JStr token)]))
        = Validity true (Some c)
      /\ c_sub c = email.
Proof.
  intros ops kv mail cfg now d email password body token
    Hspec Hiss Hbound Hp Ht Hd.
  assert (Hemail : ok_string email) by (eapply login_email_ok; exact Hp).
  assert (Hsign : Jwt.sign ops (cfg_key cfg)
    (MkClaims email (cfg_iss cfg) now (now + cfg_ttl cfg)) = Some token)
    by (eapply login_token_sign; [ exact Hp | exact Ht ]).
  assert (Hrt : Json.parse (Json.print (Claims.to_json
    (MkClaims email (cfg_iss cfg) now (now + cfg_ttl cfg))))
    = Some (Claims.to_json (MkClaims email (cfg_iss cfg) now (now + cfg_ttl cfg)))).
  { apply claims_round_trip; cbn [c_sub c_iss c_iat c_exp];
      [ exact Hemail | exact Hiss | lia | exact Hbound ]. }
  assert (Hver : Jwt.verify ops (cfg_pubkey cfg) token
    = Some (MkClaims email (cfg_iss cfg) now (now + cfg_ttl cfg)))
    by (eapply verify_sign; [ exact Hspec | exact Hrt | exact Hsign ]).
  exists (MkClaims email (cfg_iss cfg) now (now + cfg_ttl cfg)).
  split; [| reflexivity].
  unfold handle.
  rewrite (parse_token_request token
    (sign_ok_string ops (cfg_key cfg) _ token Hsign)).
  rewrite Hver. unfold Claims.fresh. cbn [c_iss c_exp].
  rewrite bytes_eqb_refl.
  replace ((now + d) <? (now + cfg_ttl cfg))%N with true
    by (symmetry; apply N.ltb_lt; lia).
  reflexivity.
Qed.

(* The honesty check: this prints what the end-to-end claim rests on.  It
   should report no axioms -- the cryptographic assumption travels in
   [crypto_spec], as a hypothesis of the theorem rather than as an axiom of
   the development. *)
Print Assumptions login_then_validate.
