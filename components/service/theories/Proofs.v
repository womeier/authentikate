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
  - destruct (Jwt.verify ops (cfg_key cfg) token) as [c |] eqn:Hv;
      [ destruct (andb (Claims.fresh now c) (bytes_eqb (c_iss c) (cfg_iss cfg))) | ];
      intros H; discriminate.
  - intros H; discriminate.
  - destruct (kv_get kv email) as [[existing |] |]; try (intros H; discriminate).
    destruct (argon2_enroll ops password) as [v |]; try (intros H; discriminate).
    destruct (Store.enrollment_record email v) as [record |];
      try (intros H; discriminate).
    destruct (kv_create kv email record) as [[|] |]; try (intros H; discriminate).
    destruct (send_email mail (cfg_email_from cfg) email
      (lit ("Welcome to Authentikate"%string))
      (lit ("Your Authentikate account has been created."%string))) as [|];
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
      kv_create kv email record = Some true /\
      send_email mail (cfg_email_from cfg) email
        (lit ("Welcome to Authentikate"%string))
        (lit ("Your Authentikate account has been created."%string)) = true.
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
  destruct (kv_create kv e record) as [[|] |] eqn:Hset; try discriminate.
  destruct (send_email mail (cfg_email_from cfg) e
    (lit ("Welcome to Authentikate"%string))
    (lit ("Your Authentikate account has been created."%string))) as [|]
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
  forall ops key token h p s,
    split_on dot token = [h; p; s] ->
    bytes_eqb h Jwt.header_b64 = false ->
    Jwt.verify ops key token = None.
Proof.
  intros ops key token h p s Hsplit Hne.
  unfold Jwt.verify. rewrite Hsplit, Hne. reflexivity.
Qed.

Definition none_header : json :=
  JObj [ (lit ("alg"%string), JStr (lit ("none"%string)));
         (lit ("typ"%string), JStr (lit ("JWT"%string))) ].

Lemma none_header_is_not_ours :
  bytes_eqb (Base64.encode (Json.print none_header)) Jwt.header_b64 = false.
Proof. vm_compute. reflexivity. Qed.

Corollary alg_none_is_rejected :
  forall ops key token p s,
    split_on dot token = [Base64.encode (Json.print none_header); p; s] ->
    Jwt.verify ops key token = None.
Proof.
  intros ops key token p s Hsplit.
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
  - destruct (Jwt.verify ops (cfg_key cfg) token) as [c' |] eqn:Hv.
    + destruct (andb (Claims.fresh now c') (bytes_eqb (c_iss c') (cfg_iss cfg))) eqn:Hg;
        intros H; inversion H; subst.
      now apply andb_prop in Hg.
    + intros H; discriminate.
  - intros H; discriminate.
  - destruct (kv_get kv email) as [[existing |] |]; try (intros H; discriminate).
    destruct (argon2_enroll ops password) as [v |]; try (intros H; discriminate).
    destruct (Store.enrollment_record email v) as [record |];
      try (intros H; discriminate).
    destruct (kv_create kv email record) as [[|] |]; try (intros H; discriminate).
    destruct (send_email mail (cfg_email_from cfg) email
      (lit ("Welcome to Authentikate"%string))
      (lit ("Your Authentikate account has been created."%string))) as [|];
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
  destruct (hmac_sign ops k (Jwt.signing_input Jwt.header_b64
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

(* The whole of what is assumed about HMAC-SHA-256, and worth reading carefully for
   what it does not say: that signing produces something verification
   accepts.  That is correctness, not security.  Unforgeability is neither
   stated nor assumed here -- assuming it would be assuming the conclusion. *)
Record crypto_spec (ops : crypto_ops) (k : Key.t) : Prop :=
  MkSpec {
    sign_verifies : forall msg sg,
      hmac_sign ops k msg = Some sg ->
      hmac_verify ops k msg sg = Some true
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
Lemma verify_parts : forall ops key h p s sg c,
  bytes_eqb h Jwt.header_b64 = true ->
  ~ bytes_In dot h -> ~ bytes_In dot p -> ~ bytes_In dot s ->
  Base64.decode s = Some sg ->
  hmac_verify ops key (BS.append h (BS.String dot p)) sg = Some true ->
  Base64.decode p = Some (Json.print (Claims.to_json c)) ->
  Json.parse (Json.print (Claims.to_json c)) = Some (Claims.to_json c) ->
  Jwt.verify ops key
    (BS.append (BS.append h (BS.String dot p)) (BS.String dot s)) = Some c.
Proof.
  intros ops key h p s sg c Hh Hdh Hdp Hds Hs Hv Hp Hrt.
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
  crypto_spec ops (cfg_key cfg) ->
  Json.parse (Json.print (Claims.to_json c)) = Some (Claims.to_json c) ->
  Jwt.sign ops (cfg_key cfg) c = Some t ->
  Jwt.verify ops (cfg_key cfg) t = Some c.
Proof.
  intros ops cfg c t Hspec Hrt H.
  unfold Jwt.sign in H. cbv zeta in H.
  destruct (hmac_sign ops (cfg_key cfg) (Jwt.signing_input Jwt.header_b64
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
  - apply (sign_verifies ops (cfg_key cfg) Hspec).
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
    crypto_spec ops (cfg_key cfg) ->
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
  assert (Hver : Jwt.verify ops (cfg_key cfg) token
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

(* ---- the security direction: accepted means authenticated --------------- *)

(* Everything above is correctness: a token this service minted validates.
   The property a caller actually wants is the converse -- that a token that
   validates was minted by this service, for an email whose password was
   checked.  That direction cannot be proved from [crypto_spec], which says
   only that signing produces something verification accepts; it says nothing
   about what else verification accepts.  So it needs an assumption, and the
   assumption is the whole of the security argument, stated where it can be
   read.

   It is deliberately a record of its own rather than a second field of
   [crypto_spec].  Adding it there would give [crypto_spec] a [signed] index
   and make [login_then_validate] -- which is correctness, and needs no
   unforgeability -- carry an assumption it does not use.  Keeping them apart
   keeps each theorem's hypotheses honest about what it rests on. *)

(* Verification accepts only messages an authorized holder authenticated.
   This idealized, message-level oracle is a security hypothesis, not a proof
   of HMAC unforgeability or a probabilistic reduction. Every holder of the
   shared secret can mint tokens, including a verifier. Instantiating [signed]
   with this service's [minted] predicate therefore also assumes that the host
   protects the key and does not provision it to other issuers. Opaque [Key.t]
   handles keep the bytes out of Rocq, not out of the provisioning host.

   Note what [signed] is not: it is not "was passed to [hmac_sign]".  It is
   a predicate the caller chooses, and the theorems below are only as strong
   as the predicate it is instantiated with.  Instantiated with [fun _ => True]
   the assumption is free and the conclusions are empty. *)
Record signing_oracle (ops : crypto_ops) (key : Key.t) (signed : bytes -> Prop)
  : Prop :=
  MkOracle {
    verify_only_signed : forall msg sg,
      hmac_verify ops key msg sg = Some true -> signed msg
  }.

(* The predicate worth instantiating it with: the messages this service signs.
   Read as a description of the [login] path -- a request parsed as a login, a
   store lookup that found a record, an Argon2 check that said yes -- plus the
   exact bytes [Jwt.sign] hands the signer for that claim set.

   The clock bound is inside the predicate rather than a hypothesis of the
   theorems because [now] is existential here: a token's claims do not say
   which request produced them, so the bound has to travel with the claim set
   it constrains.  That makes the assumption marginally stronger (verification
   accepts only messages minted under a representable clock), which is true of
   any deployment whose clock fits in 32 digits.

   What it does not say, and what no theorem here can: that the record the
   store returned is the record signup wrote for that email.  As in
   [no_token_without_verify], the store is not assumed honest. *)
Definition minted (ops : crypto_ops) (kv : store_ops) (cfg : config)
                  (msg : bytes) : Prop :=
  exists now email password body u,
    parse_request RtLogin body = Login email password /\
    Store.stored kv email = Found u /\
    argon2_verify ops password (u_salt u) (u_params u) (u_tag u) = Some true /\
    (now + cfg_ttl cfg < 10 ^ 32)%N /\
    msg = Jwt.signing_input Jwt.header_b64
            (Base64.encode (Json.print (Claims.to_json
              (MkClaims email (cfg_iss cfg) now (now + cfg_ttl cfg)%N)))).

(* [minted] is not vacuous: a successful login mints a message satisfying it.
   Worth proving, because an assumption whose predicate nothing satisfies is
   an assumption that something is unforgeable *and* never signed, and the
   theorems below would be about the empty set of tokens. *)
Lemma login_mints : forall ops kv mail cfg now body token,
  (now + cfg_ttl cfg < 10 ^ 32)%N ->
  handle ops kv mail cfg now RtLogin body = Token token ->
  exists email, minted ops kv cfg
    (Jwt.signing_input Jwt.header_b64
      (Base64.encode (Json.print (Claims.to_json
        (MkClaims email (cfg_iss cfg) now (now + cfg_ttl cfg)%N))))).
Proof.
  intros ops kv mail cfg now body token Hb H.
  apply no_token_without_verify in H as [email [password [u [Hp [Hs Ha]]]]].
  exists email, now, email, password, body, u.
  repeat split; assumption.
Qed.

(* Recovering the signed message from the dot-joined form: the header segment
   is pinned, so the payload is determined. *)
Lemma signing_input_inj : forall h p q,
  Jwt.signing_input h p = Jwt.signing_input h q -> p = q.
Proof.
  intros h p q H. unfold Jwt.signing_input in H.
  apply bytes_append_inj_l in H. injection H as H. exact H.
Qed.

(* What [verify] establishes before it will return claims.  The header
   comparison is what makes [Jwt.header_b64] appear here rather than a
   variable: a token with any other header never reaches the signature check.

   The honest limit is in the last three conjuncts.  The payload is known to
   decode and to parse to something [Claims.of_json] reads as [c] -- not to be
   [Json.print (Claims.to_json c)].  The parser accepts extra fields and
   whitespace, so distinct payloads can yield the same claims, and this lemma
   cannot pretend otherwise.  Pinning the payload needs the signing oracle
   below, which says those other payloads were never signed. *)
Lemma verify_accepts_only_signed : forall ops key token c,
  Jwt.verify ops key token = Some c ->
  exists p sg pb j,
    hmac_verify ops key (Jwt.signing_input Jwt.header_b64 p) sg = Some true /\
    Base64.decode p = Some pb /\
    Json.parse pb = Some j /\
    Claims.of_json j = Some c.
Proof.
  intros ops key token c H.
  unfold Jwt.verify in H.
  destruct (split_on dot token) as [| h [| p [| s [| extra rest]]]];
    try discriminate.
  destruct (bytes_eqb h Jwt.header_b64) eqn:Hh; [| discriminate].
  apply bytes_eqb_eq in Hh. subst h.
  destruct (Base64.decode s) as [sg |]; [| discriminate].
  destruct (hmac_verify ops key (Jwt.signing_input Jwt.header_b64 p) sg)
    as [[|] |] eqn:Hv; try discriminate.
  destruct (Base64.decode p) as [pb |] eqn:Hp; [| discriminate].
  destruct (Json.parse pb) as [j |] eqn:Hj; [| discriminate].
  exists p, sg, pb, j. repeat split; assumption.
Qed.

(* A [Validity true] answer came from a token that verified.  [validate] reads
   no store and takes no other path to a true answer. *)
Lemma validate_verifies : forall ops kv mail cfg now body c,
  handle ops kv mail cfg now RtValidate body = Validity true (Some c) ->
  exists token, Jwt.verify ops (cfg_key cfg) token = Some c.
Proof.
  intros ops kv mail cfg now body c.
  unfold handle.
  destruct (parse_request RtValidate body)
    as [email password | token | | email password] eqn:Hp.
  - destruct (Store.stored kv email) as [u | |]; intros H; try discriminate;
      exfalso; eapply login_check_not_validity, H.
  - destruct (Jwt.verify ops (cfg_key cfg) token) as [c' |] eqn:Hv.
    + destruct (andb (Claims.fresh now c') (bytes_eqb (c_iss c') (cfg_iss cfg)));
        intros H; inversion H; subst.
      exists token. exact Hv.
    + intros H; discriminate.
  - intros H; discriminate.
  - destruct (kv_get kv email) as [[existing |] |]; try (intros H; discriminate).
    destruct (argon2_enroll ops password) as [v |]; try (intros H; discriminate).
    destruct (Store.enrollment_record email v) as [record |];
      try (intros H; discriminate).
    destruct (kv_create kv email record) as [[|] |]; try (intros H; discriminate).
    destruct (send_email mail (cfg_email_from cfg) email
      (lit ("Welcome to Authentikate"%string))
      (lit ("Your Authentikate account has been created."%string))) as [|];
      intros H; discriminate.
Qed.

(* The oracle, applied at the level of [handle]: an accepted token's payload
   was signed.  Still parametric in [signed], so what it buys depends entirely
   on the predicate; the theorem after this one is the instance that says
   something. *)
Theorem accepted_was_signed :
  forall ops kv mail cfg now body c (signed : bytes -> Prop),
    signing_oracle ops (cfg_key cfg) signed ->
    handle ops kv mail cfg now RtValidate body = Validity true (Some c) ->
    exists p pb j,
      signed (Jwt.signing_input Jwt.header_b64 p) /\
      Base64.decode p = Some pb /\
      Json.parse pb = Some j /\
      Claims.of_json j = Some c.
Proof.
  intros ops kv mail cfg now body c signed [Horacle] H.
  apply validate_verifies in H as [token Hv].
  apply verify_accepts_only_signed in Hv
    as [p [sg [pb [j [Hver [Hdp [Hj Hoj]]]]]]].
  exists p, pb, j.
  split; [ eapply Horacle, Hver | repeat split; assumption ].
Qed.

(* The security statement.  An accepted token means some login happened: the
   email in the claims was looked up, a record was found, and Argon2 accepted
   the password supplied with it.  The claims are pinned exactly -- subject,
   issuer, and an [exp] that is [iat + ttl] -- which is where the signing
   oracle does its work, by ruling out the other payloads that
   [verify_accepts_only_signed] could not.

   Two hypotheses, and both are the point:
     - the oracle, instantiated at [minted ops kv cfg].  HMAC-SHA-256's
       unforgeability is doing the work, and it is assumed, not proved.
     - [ok_string (cfg_iss cfg)], the same printable-ASCII obligation
       [login_then_validate] carries, for the same reason.

   What it does not say.  Nothing about replay: a token is a bearer token and
   this says it was issued, not that it is being presented by whoever it was
   issued to.  Nothing about revocation, which [validate] cannot express.
   Nothing about which login: [issued] and [login_body] are existential, so
   two sessions for one email are indistinguishable in this statement.  And
   nothing about the store's honesty, as ever. *)
Theorem accepted_implies_authenticated :
  forall ops kv mail cfg now body c,
    signing_oracle ops (cfg_key cfg) (minted ops kv cfg) ->
    ok_string (cfg_iss cfg) ->
    handle ops kv mail cfg now RtValidate body = Validity true (Some c) ->
    exists email password u login_body issued,
      parse_request RtLogin login_body = Login email password /\
      Store.stored kv email = Found u /\
      argon2_verify ops password (u_salt u) (u_params u) (u_tag u) = Some true /\
      c = MkClaims email (cfg_iss cfg) issued (issued + cfg_ttl cfg)%N /\
      c_sub c = email /\
      Claims.fresh now c = true.
Proof.
  intros ops kv mail cfg now body c Horacle Hiss H.
  pose proof (valid_implies_fresh_and_ours _ _ _ _ _ _ _ H) as [Hfresh _].
  apply (accepted_was_signed _ _ _ _ _ _ _ _ Horacle) in H
    as [p [pb [j [Hsigned [Hdp [Hj Hoj]]]]]].
  destruct Hsigned
    as [issued [email [password [lbody [u [Hp [Hs [Ha [Hb Hmsg]]]]]]]]].
  apply signing_input_inj in Hmsg. subst p.
  rewrite base64_round_trip in Hdp.
  (* [injection] here would normalize [Json.print] into its byte chain and
     bury the goal; [congruence] keeps the terms as written. *)
  assert (Hpb : Json.print (Claims.to_json
      (MkClaims email (cfg_iss cfg) issued (issued + cfg_ttl cfg)%N)) = pb)
    by congruence.
  rewrite <- Hpb in Hj.
  rewrite claims_round_trip in Hj;
    [ | cbn [c_sub]; eapply login_email_ok, Hp
      | cbn [c_iss]; exact Hiss
      | cbn [c_iat]; lia
      | cbn [c_exp]; exact Hb ].
  assert (Hj' : Claims.to_json
      (MkClaims email (cfg_iss cfg) issued (issued + cfg_ttl cfg)%N) = j)
    by congruence.
  rewrite <- Hj', of_json_to_json in Hoj.
  assert (Hc : MkClaims email (cfg_iss cfg) issued (issued + cfg_ttl cfg)%N = c)
    by congruence.
  exists email, password, u, lbody, issued.
  repeat split;
    [ exact Hp | exact Hs | exact Ha | now rewrite <- Hc
    | now rewrite <- Hc | exact Hfresh ].
Qed.

(* Again, no axioms: the cryptographic assumption travels in [signing_oracle]
   and the clock bound inside [minted], both as hypotheses. *)
Print Assumptions accepted_implies_authenticated.

(* ---- the forgery statement ---------------------------------------------- *)

(* What the two theorems above say positively; this is the same content as a
   rejection, which is the shape an attacker cares about.  Stated so that it
   leans on the provider's assumption and on as little else as possible: the
   only hypotheses are the signing oracle and the absence of a password that
   the Argon2 provider accepts for any record the store will return.

   In particular no [ok_string], no clock bound, no well-formedness of the
   token, the body, or the configuration, and nothing about the store beyond
   what it answers.  The token is an arbitrary request body: whatever bytes an
   attacker sends, [validate] does not answer [true].

   It follows from [accepted_was_signed], so the only thing standing between a
   forged token and a [valid: true] is HMAC-SHA-256's unforgeability as assumed in
   [signing_oracle].  The price of asking for so little is that the Argon2
   hypothesis is quantified over every email: without the claims round trip
   there is nothing tying [c] to the account it names, which is what the next
   corollary pays [ok_string] for. *)
Corollary no_valid_token_without_a_password :
  forall ops kv mail cfg now body c,
    signing_oracle ops (cfg_key cfg) (minted ops kv cfg) ->
    (forall email password u,
       Store.stored kv email = Found u ->
       argon2_verify ops password (u_salt u) (u_params u) (u_tag u) <> Some true) ->
    handle ops kv mail cfg now RtValidate body <> Validity true (Some c).
Proof.
  intros ops kv mail cfg now body c Horacle Hno H.
  apply (accepted_was_signed _ _ _ _ _ _ _ _ Horacle) in H
    as [p [pb [j [Hsigned _]]]].
  destruct Hsigned as [issued [email [password [lbody [u [Hp [Hs [Ha _]]]]]]]].
  exact (Hno email password u Hs Ha).
Qed.

(* No axioms: the forgery statement rests on the oracle and nothing else. *)
Print Assumptions no_valid_token_without_a_password.

(* The sharper reading, for one account rather than all of them: a token whose
   subject is an account nobody can authenticate does not validate, even while
   other accounts are being logged into normally.  This is the statement a
   deployment wants about a single user, and it costs one hypothesis that is
   not the provider's -- [ok_string (cfg_iss cfg)], the printable-ASCII
   obligation on the issuer the host installs, which is what pins the claims
   to the email they name. *)
Corollary no_valid_token_for_an_unauthenticated_account :
  forall ops kv mail cfg now body c,
    signing_oracle ops (cfg_key cfg) (minted ops kv cfg) ->
    ok_string (cfg_iss cfg) ->
    (forall password u,
       Store.stored kv (c_sub c) = Found u ->
       argon2_verify ops password (u_salt u) (u_params u) (u_tag u) <> Some true) ->
    handle ops kv mail cfg now RtValidate body <> Validity true (Some c).
Proof.
  intros ops kv mail cfg now body c Horacle Hiss Hno H.
  apply (accepted_implies_authenticated _ _ _ _ _ _ _ Horacle Hiss) in H
    as [email [password [u [lbody [issued [Hp [Hs [Ha [Hc [Hsub _]]]]]]]]]].
  rewrite Hsub in Hno. exact (Hno password u Hs Ha).
Qed.

(* ---- what the service refuses to say ------------------------------------ *)

(* Signup discloses whether an email is taken; that is a decision, recorded in
   PLAN.md.  Login must not, and the two statements below are the part of that
   promise which lives in the logic rather than in a measurement.

   This first one is about [login_check] because that is where the choice is
   made: [found] selects the salt, parameters and tag, but it also sits in the
   second position of the match, so a failing hash yields [Unauthorized]
   whichever way it went.  No hypothesis about the dummy credentials is
   needed -- not even that the dummy tag fails to verify -- because the
   [None] case cannot produce a token at all. *)
Lemma login_check_hides_existence : forall ops cfg now email password u,
  argon2_verify ops password (u_salt u) (u_params u) (u_tag u) <> Some true ->
  login_check ops cfg (Some u) email now password
    = login_check ops cfg None email now password.
Proof.
  intros ops cfg now email password u Hno.
  unfold login_check. cbn.
  destruct (argon2_verify ops password (u_salt u) (u_params u) (u_tag u))
    as [[|] |]; [ congruence | | ];
    destruct (argon2_verify ops password (cfg_dummy_salt cfg)
                (cfg_dummy_params cfg) (cfg_dummy_tag cfg)) as [[|] |];
    reflexivity.
Qed.

(* And the same thing about the service: a wrong password against an account
   that exists is the same response as any password against an account that
   does not.  Two store records rather than one state, as in [store_creates],
   because the model has no state: [kv] answers [Absent] for this email and
   [kv'] answers [Found u], and the answers [handle] gives are equal.

   What it is not.  It is a statement about the response *value*, so it says
   nothing about how long either path takes -- the reason [login_check] runs
   Argon2 either way is timing, and timing is not visible here.  It also says
   nothing about [Unavailable]: a store that refuses answers [Internal], which
   is distinguishable, and deliberately so, since a 500 is no evidence about
   whether the account exists. *)
Theorem login_hides_existence :
  forall ops kv kv' mail cfg now body email password u,
    parse_request RtLogin body = Login email password ->
    Store.stored kv email = Absent ->
    Store.stored kv' email = Found u ->
    argon2_verify ops password (u_salt u) (u_params u) (u_tag u) <> Some true ->
    handle ops kv mail cfg now RtLogin body
      = handle ops kv' mail cfg now RtLogin body.
Proof.
  intros ops kv kv' mail cfg now body email password u Hp Habs Hfound Hno.
  unfold handle. rewrite Hp, Habs, Hfound.
  symmetry. now apply login_check_hides_existence.
Qed.

(* [parse_request] on the validate route produces only the two things the
   route can mean.  Stated because [handle] matches on a [request] rather than
   on a route, so a proof about one route has to rule the others out. *)
Lemma validate_request_shape : forall body,
  parse_request RtValidate body = Malformed
  \/ exists token, parse_request RtValidate body = Validate token.
Proof.
  intros body.
  (* The blacklist keeps [get_str] and [lit] folded, so the destruct below
     abstracts a term the goal still contains. *)
  cbn -[Json.parse Json.get_str lit].
  destruct (Json.parse body) as [j |]; [| now left ].
  destruct (Json.get_str (lit ("token"%string)) j) as [t |]; [| now left ].
  right. now exists t.
Qed.

(* Validation does not read the store, and this says so: any two stores give
   the same answer.  Both halves of that are worth having.  It is the reason
   validation scales past the store -- a token carries its claims and its
   signature, so checking one is arithmetic -- and it is the exact shape of
   the revocation limit: no state a deployment can reach makes a fresh,
   well-signed token stop validating.  Revocation is not missing from
   [validate] by omission, it is excluded by this equality. *)
Theorem validate_ignores_the_store :
  forall ops kv kv' mail cfg now body,
    handle ops kv mail cfg now RtValidate body
      = handle ops kv' mail cfg now RtValidate body.
Proof.
  intros ops kv kv' mail cfg now body.
  destruct (validate_request_shape body) as [Hm | [token Ht]];
    unfold handle; [ rewrite Hm | rewrite Ht ]; reflexivity.
Qed.

(* Neither of these rests on anything: no oracle, no [crypto_spec], no bound,
   no well-formedness.  Worth printing for exactly that reason. *)
Print Assumptions login_hides_existence.
Print Assumptions validate_ignores_the_store.

(* ---- the account lifecycle ---------------------------------------------- *)

(* [created_requires_persistence] says a 201 means a write was acknowledged.
   It does not say the account can then be used, which is the property a
   caller of [signup] actually wants, and the one piece of the service that
   had no theorem.  Three things stand between the two statements, and each
   is dealt with differently below: what Argon2 promises about an enrollment
   (assumed), what the store does with a write (assumed, and this is the
   interesting one), and whether the record this module writes can be read
   back (proved). *)

(* The stored record, read back.  [enrollment_record] prints an object of its
   own rather than the component's JSON with an email prepended, and this is
   the lemma that spends the difference: the eight fields are literal keys
   over leaf values the parser accepts, so [parse_print_obj] applies.  The
   old shape could not be read back in a proof at all -- a provider field
   holding a nested object is printable and reparsable, but not by a theorem
   this development has. *)
Lemma record_json_round_trip : forall email p,
  ok_string email -> ok_string (pr_salt64 p) -> ok_string (pr_tag64 p) ->
  (ap_algorithm (pr_params p) < 10 ^ 32)%N ->
  (ap_memory_kib (pr_params p) < 10 ^ 32)%N ->
  (ap_iterations (pr_params p) < 10 ^ 32)%N ->
  (ap_parallelism (pr_params p) < 10 ^ 32)%N ->
  (ap_tag_length (pr_params p) < 10 ^ 32)%N ->
  Json.parse (Json.print (Store.record_json email p))
    = Some (Store.record_json email p).
Proof.
  intros email p He Hs Ht H1 H2 H3 H4 H5.
  unfold Store.record_json.
  apply parse_print_obj.
  - cbn [Datatypes.length]. lia.
  - apply Forall_cons; [ split; [ ok_literal | exact He ] |].
    apply Forall_cons; [ split; [ ok_literal | exact Hs ] |].
    apply Forall_cons; [ split; [ ok_literal | exact Ht ] |].
    apply Forall_cons; [ split; [ ok_literal | exact H1 ] |].
    apply Forall_cons; [ split; [ ok_literal | exact H2 ] |].
    apply Forall_cons; [ split; [ ok_literal | exact H3 ] |].
    apply Forall_cons; [ split; [ ok_literal | exact H4 ] |].
    apply Forall_cons; [ split; [ ok_literal | exact H5 ] |].
    apply Forall_nil.
  - cbn. repeat split; (reflexivity || exact I).
Qed.

(* And the conditions it asks for, discharged from the component's JSON: the
   two base64 strings came out of the parser, and the five cost fields passed
   [fits_u32], which is a far tighter bound than the printer needs. *)
Lemma public_of_json_facts : forall j p,
  json_ok j -> Store.public_of_json j = Some p ->
  ok_string (pr_salt64 p) /\ ok_string (pr_tag64 p) /\
  (ap_algorithm (pr_params p) < 10 ^ 32)%N /\
  (ap_memory_kib (pr_params p) < 10 ^ 32)%N /\
  (ap_iterations (pr_params p) < 10 ^ 32)%N /\
  (ap_parallelism (pr_params p) < 10 ^ 32)%N /\
  (ap_tag_length (pr_params p) < 10 ^ 32)%N.
Proof.
  intros j p Hok H. unfold Store.public_of_json in H.
  destruct (Json.get_str (lit ("salt"%string)) j) as [salt64 |] eqn:Esalt;
    [| discriminate].
  destruct (Json.get_str (lit ("tag"%string)) j) as [tag64 |] eqn:Etag;
    [| discriminate].
  destruct (Json.get_num (lit ("algorithm"%string)) j) as [alg |];
    [| discriminate].
  destruct (Json.get_num (lit ("memory_kib"%string)) j) as [mem |];
    [| discriminate].
  destruct (Json.get_num (lit ("iterations"%string)) j) as [iter |];
    [| discriminate].
  destruct (Json.get_num (lit ("parallelism"%string)) j) as [par |];
    [| discriminate].
  destruct (Json.get_num (lit ("tag_length"%string)) j) as [len |];
    [| discriminate].
  destruct (andb (andb (andb (Store.fits_u32 alg) (Store.fits_u32 mem))
                       (andb (Store.fits_u32 iter) (Store.fits_u32 par)))
                 (Store.fits_u32 len)) eqn:Hfit; [| discriminate].
  injection H as E. subst p.
  unfold Store.fits_u32 in Hfit.
  repeat (apply andb_prop in Hfit as [Hfit ?]).
  cbn [pr_salt64 pr_tag64 pr_params ap_algorithm ap_memory_kib ap_iterations
       ap_parallelism ap_tag_length].
  apply andb_prop in H0 as [H2 H3].
  apply N.ltb_lt in Hfit, H1, H2, H3, H.
  split; [ eapply get_str_ok; [ exact Hok | exact Esalt ] |].
  split; [ eapply get_str_ok; [ exact Hok | exact Etag ] |].
  repeat split; lia.
Qed.

(* What [of_json] makes of a record this module printed.  The eight lookups
   are decided by conversion; [fits_u32] is kept folded through the reduction
   because the hypothesis is the only thing that can discharge it -- the
   parameters are variables, and the test is run a second time on the way
   back in. *)
Lemma of_json_record_json : forall j email p,
  Store.public_of_json j = Some p ->
  Store.of_json (Store.record_json email p)
    = match Base64.decode (pr_salt64 p), Base64.decode (pr_tag64 p) with
      | Some salt, Some tag =>
          Some (MkUser email salt (pr_params p) (Secret.of_bytes tag))
      | _, _ => None
      end.
Proof.
  intros j email p Hp.
  unfold Store.public_of_json in Hp.
  destruct (Json.get_str (lit ("salt"%string)) j) as [salt64 |];
    [| discriminate].
  destruct (Json.get_str (lit ("tag"%string)) j) as [tag64 |]; [| discriminate].
  destruct (Json.get_num (lit ("algorithm"%string)) j) as [alg |];
    [| discriminate].
  destruct (Json.get_num (lit ("memory_kib"%string)) j) as [mem |];
    [| discriminate].
  destruct (Json.get_num (lit ("iterations"%string)) j) as [iter |];
    [| discriminate].
  destruct (Json.get_num (lit ("parallelism"%string)) j) as [par |];
    [| discriminate].
  destruct (Json.get_num (lit ("tag_length"%string)) j) as [len |];
    [| discriminate].
  destruct (andb (andb (andb (Store.fits_u32 alg) (Store.fits_u32 mem))
                       (andb (Store.fits_u32 iter) (Store.fits_u32 par)))
                 (Store.fits_u32 len)) eqn:Hfit; [| discriminate].
  injection Hp as Ep. subst p.
  unfold Store.of_json, Store.record_json, Store.public_of_json.
  cbn -[Store.fits_u32 Base64.decode].
  rewrite Hfit.
  cbn -[Base64.decode].
  reflexivity.
Qed.

Lemma record_email_safe_ok : forall email,
  Store.record_email_safe email = true <-> ok_string email.
Proof.
  intros email.
  assert (E : Store.record_email_safe email = ok_stringb email).
  { induction email as [| b rest IH]; [reflexivity |].
    change (andb (ok_byteb b) (Store.record_email_safe rest) =
            andb (ok_byteb b) (ok_stringb rest)).
    now rewrite IH. }
  rewrite E. clear E. split; [apply ok_stringb_ok |].
  intros H. induction email as [| b rest IH]; [reflexivity |].
  cbn [ok_stringb]. apply andb_true_iff. split.
  - apply (proj2 (ok_string_pointwise _) H). unfold bytes_In. now left.
  - apply IH. apply ok_string_pointwise. intros c Hin.
    apply (proj2 (ok_string_pointwise _) H). unfold bytes_In in *.
    now right.
Qed.

(* Equality with the former print/decode implementation for parser-safe emails,
   including malformed provider JSON and the exact bytes on success. *)
Theorem enrollment_record_equivalent : forall email public_json,
  ok_string email ->
  Store.enrollment_record email public_json =
  match Json.parse public_json with
  | Some j =>
      match Json.get (lit ("email"%string)) j, Store.public_of_json j with
      | None, Some p =>
          let v := Json.print (Store.record_json email p) in
          match Store.decode v with
          | Some _ => Some v
          | None => None
          end
      | _, _ => None
      end
  | None => None
  end.
Proof.
  intros email pj He. unfold Store.enrollment_record.
  destruct (Json.parse pj) as [j |] eqn:Ej; [| reflexivity].
  destruct (Json.get (lit ("email"%string)) j); [reflexivity |].
  destruct (Store.public_of_json j) as [p |] eqn:Ep; [| reflexivity].
  rewrite (proj2 (record_email_safe_ok email) He).
  pose proof (public_of_json_facts _ _ (parse_json_ok _ _ Ej) Ep)
    as [Hs [Ht [B1 [B2 [B3 [B4 B5]]]]]].
  unfold Store.decode.
  rewrite record_json_round_trip by assumption.
  rewrite (of_json_record_json _ _ _ Ep).
  destruct (Base64.decode (pr_salt64 p));
    destruct (Base64.decode (pr_tag64 p)); reflexivity.
Qed.

Print Assumptions enrollment_record_equivalent.

(* The whole of it: what signup wrote is a record naming the email signup was
   asked for, carrying the salt, parameters and tag the component returned.
   The email is the part that matters -- [Store.stored] answers [Absent] for
   a record belonging to someone else, so without this a created account
   would be indistinguishable from one that was never created. *)
Lemma enrollment_record_decode : forall email pj v,
  ok_string email ->
  Store.enrollment_record email pj = Some v ->
  exists j p salt tag,
    Json.parse pj = Some j /\
    Store.public_of_json j = Some p /\
    Base64.decode (pr_salt64 p) = Some salt /\
    Base64.decode (pr_tag64 p) = Some tag /\
    Store.decode v = Some (MkUser email salt (pr_params p) (Secret.of_bytes tag)).
Proof.
  intros email pj v He H. rewrite enrollment_record_equivalent in H by exact He.
  destruct (Json.parse pj) as [j |] eqn:Ej; [| discriminate].
  destruct (Json.get (lit ("email"%string)) j) as [x |]; [discriminate |].
  destruct (Store.public_of_json j) as [p |] eqn:Ep; [| discriminate].
  cbv zeta in H.
  pose proof (parse_json_ok _ _ Ej) as Hj.
  pose proof (public_of_json_facts _ _ Hj Ep) as [Hs [Ht [B1 [B2 [B3 [B4 B5]]]]]].
  assert (Hdec : Store.decode (Json.print (Store.record_json email p))
                 = Store.of_json (Store.record_json email p)).
  { unfold Store.decode. now rewrite record_json_round_trip. }
  rewrite Hdec, (of_json_record_json _ _ _ Ep) in H.
  destruct (Base64.decode (pr_salt64 p)) as [salt |] eqn:Esalt; [| discriminate].
  destruct (Base64.decode (pr_tag64 p)) as [tag |] eqn:Etag; [| discriminate].
  (* [subst v] would normalise [print] into its byte chain and leave a goal
     no rewrite can reach; the equation is kept folded instead. *)
  assert (Hv : Json.print (Store.record_json email p) = v) by congruence.
  exists j, p, salt, tag.
  split; [ reflexivity |].
  split; [ exact Ep |].
  split; [ exact Esalt |].
  split; [ exact Etag |].
  rewrite <- Hv, Hdec, (of_json_record_json _ _ _ Ep), Esalt, Etag.
  reflexivity.
Qed.

(* Signup and login read the same two fields out of the same body; only the
   route decides which constructor comes back.  So a body that signed an
   account up is a body that can log it in, which is what lets the lifecycle
   theorem below quantify over one body rather than two. *)
Lemma signup_is_login : forall body email password,
  parse_request RtSignup body = Signup email password ->
  parse_request RtLogin body = Login email password.
Proof.
  intros body email password H. unfold parse_request in H |- *.
  destruct (Json.parse body) as [j |]; [| discriminate].
  destruct (Json.get_str (lit ("email"%string)) j) as [e |]; [| discriminate].
  destruct (Json.get_str (lit ("password"%string)) j) as [pw |];
    [| discriminate].
  injection H as E1 E2. now subst.
Qed.

(* Every email reaching enrollment from signup passes the defensive guard. *)
Corollary signup_email_record_safe : forall body email password,
  parse_request RtSignup body = Signup email password ->
  Store.record_email_safe email = true.
Proof.
  intros body email password H. apply record_email_safe_ok.
  exact (login_email_ok _ _ _ (signup_is_login _ _ _ H)).
Qed.

(* The second trust boundary, and the counterpart of [crypto_spec]: what the
   Argon2 component promises about itself.  Stated over [public_of_json] --
   the component's own output, with no serialization of this module's in
   between -- so that a bug in [enrollment_record] cannot hide inside the
   assumption.  Like [crypto_spec] this is correctness and not security: it
   says an enrollment verifies against the password it was made from, and
   says nothing about what else verifies. *)
Record argon2_spec (ops : crypto_ops) : Prop :=
  MkArgon2Spec {
    enroll_verifies : forall password pj j p salt tag,
      argon2_enroll ops password = Some pj ->
      Json.parse pj = Some j ->
      Store.public_of_json j = Some p ->
      Base64.decode (pr_salt64 p) = Some salt ->
      Base64.decode (pr_tag64 p) = Some tag ->
      argon2_verify ops password salt (pr_params p) (Secret.of_bytes tag)
        = Some true
  }.

(* And the storage assumption, which is the one worth arguing about.  There
   is no state in this model -- [store_ops] is a record of functions -- so
   "the account is there afterwards" cannot be said of one store.  It is said
   of two: the store signup ran against, and the store a later caller runs
   against, related by the two promises this service needs.

   [create_then_get] is read-your-write.  [create_is_exclusive] is the
   atomicity of the create, written as the only thing atomicity buys a
   caller: two callers cannot both be told they created the same key, in
   either order and for any values.  It is what [kv_get] followed by a plain
   [set] could not promise, and it is what the accounts provider's atomic create
   must earn -- for a store that merely overwrites, [kv_create] cannot be
   implemented at all, which is the point of taking it as a primitive rather
   than building it here.

   What they still do not say: that the write is durable, that a record once
   created is never deleted or replaced by something outside this service, or
   anything about the order two concurrent callers are served in.  A store
   that satisfies both and loses the account to a disk failure a moment later
   is entirely possible; see PLAN.md. *)
Record store_creates (kv kv' : store_ops) : Prop :=
  MkCreates {
    create_then_get : forall key v,
      kv_create kv key v = Some true -> kv_get kv' key = Some (Some v);
    create_is_exclusive : forall key v v',
      kv_create kv key v = Some true -> kv_create kv' key v' <> Some true
  }.

(* An account that was created can log in.  The signing hypothesis is not
   decoration: [Jwt.sign] returning [None] is a 500, so without it the
   honest conclusion would be "a token or an internal error", which is not
   worth stating.  Note that no credential appears in the hypotheses beyond
   the body itself -- the password that signed up is the password that logs
   in because it is the same [body]. *)
Theorem signup_then_login :
  forall ops kv kv' mail cfg now now' email password body,
    argon2_spec ops ->
    store_creates kv kv' ->
    (forall msg, hmac_sign ops (cfg_key cfg) msg <> None) ->
    parse_request RtSignup body = Signup email password ->
    handle ops kv mail cfg now RtSignup body = Created ->
    exists token, handle ops kv' mail cfg now' RtLogin body = Token token.
Proof.
  intros ops kv kv' mail cfg now now' email password body
    [Hargon] [Hcommit Hexcl] Hsign Hp Hcreated.
  pose proof (login_email_ok _ _ _ (signup_is_login _ _ _ Hp)) as He.
  unfold handle in Hcreated. rewrite Hp in Hcreated.
  destruct (kv_get kv email) as [[existing |] |]; try discriminate.
  destruct (argon2_enroll ops password) as [pj |] eqn:Epj; [| discriminate].
  destruct (Store.enrollment_record email pj) as [v |] eqn:Ev; [| discriminate].
  destruct (kv_create kv email v) as [[|] |] eqn:Eset; try discriminate.
  apply enrollment_record_decode in Ev as
    [j [p [salt [tag [Ej [Ep [Esalt [Etag Edec]]]]]]]]; [| exact He].
  unfold handle. rewrite (signup_is_login _ _ _ Hp).
  unfold Store.stored. rewrite (Hcommit _ _ Eset), Edec.
  cbn [u_email]. rewrite bytes_eqb_refl.
  unfold login_check. cbn [u_salt u_params u_tag].
  rewrite (Hargon _ _ _ _ _ _ Epj Ej Ep Esalt Etag).
  unfold Jwt.sign. cbv zeta.
  destruct (hmac_sign ops (cfg_key cfg) (Jwt.signing_input Jwt.header_b64
    (Base64.encode (Json.print (Claims.to_json
      (MkClaims email (cfg_iss cfg) now' (now' + cfg_ttl cfg)%N))))))
    as [sg |] eqn:Es; [| now exfalso; eapply Hsign, Es].
  eexists. reflexivity.
Qed.

(* [login_then_validate] over the bytes the host actually sends back.  The
   object it builds by hand *is* [render (Token token)]; saying so costs one
   [unfold] and removes the question of whether the theorem is about the
   response or about something that resembles it. *)
Corollary login_then_validate_wire :
  forall ops kv mail cfg now d email password body token,
    crypto_spec ops (cfg_key cfg) ->
    ok_string (cfg_iss cfg) ->
    (now + cfg_ttl cfg < 10 ^ 32)%N ->
    parse_request RtLogin body = Login email password ->
    handle ops kv mail cfg now RtLogin body = Token token ->
    (d < cfg_ttl cfg)%N ->
    exists c,
      handle ops kv mail cfg (now + d) RtValidate (render (Token token))
        = Validity true (Some c)
      /\ c_sub c = email.
Proof.
  intros ops kv mail cfg now d email password body token Hspec Hiss Hb Hp Ht Hd.
  unfold render.
  eapply login_then_validate; eassumption.
Qed.

(* Signup, login, validate: the three endpoints in sequence, over one request
   body and one token, with every cryptographic and storage promise a
   hypothesis.  This is the service's functional claim stated once.

   What it is not: a liveness or availability result (every hypothesis is an
   implication, and a store that refuses everything satisfies none of them
   vacuously but also answers 500 honestly), a uniqueness result (two
   concurrent signups can both reach [Created] against stores that each
   satisfy [store_creates]), or a security result -- for the converse
   direction see [accepted_implies_authenticated]. *)
Corollary signup_then_validate :
  forall ops kv kv' mail cfg now now' d email password body,
    argon2_spec ops ->
    store_creates kv kv' ->
    crypto_spec ops (cfg_key cfg) ->
    (forall msg, hmac_sign ops (cfg_key cfg) msg <> None) ->
    ok_string (cfg_iss cfg) ->
    (now' + cfg_ttl cfg < 10 ^ 32)%N ->
    (d < cfg_ttl cfg)%N ->
    parse_request RtSignup body = Signup email password ->
    handle ops kv mail cfg now RtSignup body = Created ->
    exists token c,
      handle ops kv' mail cfg now' RtLogin body = Token token /\
      handle ops kv' mail cfg (now' + d) RtValidate (render (Token token))
        = Validity true (Some c) /\
      c_sub c = email.
Proof.
  intros ops kv kv' mail cfg now now' d email password body
    Hargon Hcommit Hspec Hsign Hiss Hb Hd Hp Hcreated.
  destruct (signup_then_login ops kv kv' mail cfg now now' email password body
    Hargon Hcommit Hsign Hp Hcreated) as [token Htoken].
  destruct (login_then_validate_wire ops kv' mail cfg now' d email password body
    token Hspec Hiss Hb (signup_is_login _ _ _ Hp) Htoken Hd)
    as [c [Hvalid Hsub]].
  exists token, c. repeat split; assumption.
Qed.

(* Five hypotheses and no axioms: Argon2, HMAC-SHA-256 and the store all travel in
   the statement. *)
Print Assumptions signup_then_validate.

(* And the account is created once.  This is the theorem the store change was
   for: two signups naming the same email, in either order and with any two
   passwords, cannot both be answered [Created].  Before [kv_create] it was
   not provable and it was not true -- the read and the write were separate
   operations, so two callers could both read [Some None] and both write, and
   the second silently replaced the first's account.

   The hypothesis doing the work is [create_is_exclusive], and it is an
   assumption about the store, not a theorem about this file: what is proved
   here is that signup rests the account's uniqueness on that one primitive
   and on nothing else -- not on the read above it, not on the order the two
   requests arrive in, and not on there being only one process. *)
Theorem signup_happens_once :
  forall ops kv kv' mail cfg now now' email password password' body body',
    store_creates kv kv' ->
    parse_request RtSignup body = Signup email password ->
    parse_request RtSignup body' = Signup email password' ->
    handle ops kv mail cfg now RtSignup body = Created ->
    handle ops kv' mail cfg now' RtSignup body' <> Created.
Proof.
  intros ops kv kv' mail cfg now now' email password password' body body'
    [_ Hexcl] Hp Hp' H1 H2.
  apply created_requires_persistence in H1
    as [e1 [pw1 [pj1 [r1 [Hq1 [_ [_ [_ [_ [Hc1 _]]]]]]]]]].
  apply created_requires_persistence in H2
    as [e2 [pw2 [pj2 [r2 [Hq2 [_ [_ [_ [_ [Hc2 _]]]]]]]]]].
  rewrite Hp in Hq1. rewrite Hp' in Hq2.
  injection Hq1 as <- _. injection Hq2 as <- _.
  exact (Hexcl _ _ _ Hc1 Hc2).
Qed.

(* No axioms: exclusivity travels in [store_creates] as a hypothesis. *)
Print Assumptions signup_happens_once.

(* ---- what the client gets ----------------------------------------------- *)

(* [render] turns a response into bytes and nothing in this file used to say
   anything about them.  For the token response that was almost an accident --
   [parse_token_request] is exactly that object -- but the validation response
   is nested, and nesting is what [parse_print_obj] could not reach.  With
   the general round trip in JsonProofs.v it can be said properly: a client
   parsing a validation response reads back the claim set the service
   validated, field for field. *)

Lemma claims_value_ok : forall c,
  ok_string (c_sub c) -> ok_string (c_iss c) ->
  (c_iat c < 10 ^ 32)%N -> (c_exp c < 10 ^ 32)%N ->
  value_ok (Claims.to_json c).
Proof.
  intros [sub iss iat exp] Hsub Hiss Hiat Hexp.
  cbn [c_sub c_iss c_iat c_exp] in Hsub, Hiss, Hiat, Hexp.
  unfold Claims.to_json. cbn [c_sub c_iss c_iat c_exp].
  apply value_ok_obj.
  - apply value_fields_cons; [ ok_literal | now apply value_ok_str |].
    apply value_fields_cons; [ ok_literal | now apply value_ok_str |].
    apply value_fields_cons; [ ok_literal | now apply value_ok_num |].
    apply value_fields_cons; [ ok_literal | now apply value_ok_num |].
    apply value_fields_nil.
  - cbn. repeat split; (reflexivity || exact I).
Qed.

(* Six of the parser's sixteen, for the deepest thing this service prints. *)
Lemma claims_fuel : forall c, value_fuel (Claims.to_json c) = 6%nat.
Proof. intros c. reflexivity. Qed.

(* The nested response, read back.  [Json.get] of the two fields is settled by
   conversion, and the claims field is [to_json c] on the nose -- so a client
   recovers [c] itself rather than something that agrees with it on the four
   fields it thought to look at. *)
Theorem validity_reads_back : forall v c,
  ok_string (c_sub c) -> ok_string (c_iss c) ->
  (c_iat c < 10 ^ 32)%N -> (c_exp c < 10 ^ 32)%N ->
  exists j cj,
    Json.parse (render (Validity v (Some c))) = Some j /\
    Json.get (lit ("valid"%string)) j = Some (JBool v) /\
    Json.get (lit ("claims"%string)) j = Some cj /\
    Claims.of_json cj = Some c.
Proof.
  intros v c Hsub Hiss Hiat Hexp.
  exists (JObj [(lit ("valid"%string), JBool v);
                (lit ("claims"%string), Claims.to_json c)]).
  exists (Claims.to_json c).
  unfold render.
  split.
  - apply parse_print.
    + apply value_ok_obj.
      * apply value_fields_cons; [ ok_literal | apply value_ok_bool |].
        apply value_fields_cons; [ ok_literal | now apply claims_value_ok |].
        apply value_fields_nil.
      * cbn. repeat split; (reflexivity || exact I).
    + cbn. lia.
  - split; [ reflexivity |].
    split; [ reflexivity | apply of_json_to_json ].
Qed.

(* And the whole of [render]: the service never puts a body on the wire that
   its own parser would reject.  The conditions are on what the response
   carries, because that is the only part [render] does not choose: the keys
   and the error strings are literals. *)
Definition response_ok (r : response) : Prop :=
  match r with
  | Token t => ok_string t
  | Validity _ (Some c) =>
      ok_string (c_sub c) /\ ok_string (c_iss c) /\
      (c_iat c < 10 ^ 32)%N /\ (c_exp c < 10 ^ 32)%N
  | _ => True
  end.

Ltac flat_response :=
  apply parse_print;
  [ apply value_ok_obj;
    [ repeat (apply value_fields_cons;
                [ ok_literal
                | (apply value_ok_bool
                   || (apply value_ok_str; (ok_literal || assumption))) |]);
      apply value_fields_nil
    | cbn; repeat split; (reflexivity || exact I) ]
  | cbn; lia ].

Theorem render_parses : forall r,
  response_ok r -> exists j, Json.parse (render r) = Some j.
Proof.
  intros r Hr. destruct r as [t | v [c |] | | | | |]; cbn [response_ok] in Hr.
  - eexists. unfold render. flat_response.
  - destruct Hr as [H1 [H2 [H3 H4]]].
    destruct (validity_reads_back v c H1 H2 H3 H4) as [j [cj [Hj _]]].
    now exists j.
  - eexists. unfold render. flat_response.
  - eexists. unfold render. flat_response.
  - eexists. unfold render. flat_response.
  - eexists. unfold render. flat_response.
  - eexists. unfold render. flat_response.
  - eexists. unfold render. flat_response.
Qed.

(* Two of [response_ok]'s four conditions come for free on the validate path:
   the claims were read out of a parsed payload, and the parser only produces
   printable escape-free strings. *)
Lemma of_json_claims_ok : forall j c,
  json_ok j -> Claims.of_json j = Some c ->
  ok_string (c_sub c) /\ ok_string (c_iss c).
Proof.
  intros j c Hj H. unfold Claims.of_json in H.
  destruct (Json.get_str (lit ("sub"%string)) j) as [sub |] eqn:Es;
    [| discriminate].
  destruct (Json.get_str (lit ("iss"%string)) j) as [iss |] eqn:Ei;
    [| discriminate].
  destruct (Json.get_num (lit ("iat"%string)) j) as [iat |]; [| discriminate].
  destruct (Json.get_num (lit ("exp"%string)) j) as [exp |]; [| discriminate].
  injection H as E. subst c. cbn [c_sub c_iss].
  split; [ eapply get_str_ok; [ exact Hj | exact Es ]
         | eapply get_str_ok; [ exact Hj | exact Ei ] ].
Qed.

Lemma validated_claims_strings : forall ops kv mail cfg now body c,
  handle ops kv mail cfg now RtValidate body = Validity true (Some c) ->
  ok_string (c_sub c) /\ ok_string (c_iss c).
Proof.
  intros ops kv mail cfg now body c H.
  apply validate_verifies in H as [token Hv].
  apply verify_accepts_only_signed in Hv
    as [p [sg [pb [j [Hver [Hdp [Hj Hoj]]]]]]].
  eapply of_json_claims_ok; [ eapply parse_json_ok, Hj | exact Hoj ].
Qed.

(* The other two do not, and the reason is worth recording: [N_of_decimal]
   reads a numeral of any length, while [decimal_of_N] has a 32-digit budget,
   so a claim set naming a timestamp at or above [10 ^ 32] would be printed
   wrong -- the service would misreport a token it had just accepted.  No
   token this service mints is like that ([minted] carries the bound), so
   under [signing_oracle] the two hypotheses are discharged rather than
   assumed; without it they are the honest statement of a printer limit. *)
Corollary validated_claims_reach_the_client :
  forall ops kv mail cfg now body c,
    (c_iat c < 10 ^ 32)%N -> (c_exp c < 10 ^ 32)%N ->
    handle ops kv mail cfg now RtValidate body = Validity true (Some c) ->
    exists j cj,
      Json.parse (render (Validity true (Some c))) = Some j /\
      Json.get (lit ("valid"%string)) j = Some (JBool true) /\
      Json.get (lit ("claims"%string)) j = Some cj /\
      Claims.of_json cj = Some c.
Proof.
  intros ops kv mail cfg now body c Hiat Hexp H.
  destruct (validated_claims_strings _ _ _ _ _ _ _ H) as [Hsub Hiss].
  now apply validity_reads_back.
Qed.

(* Nothing new is assumed by any of this: the round trip is a theorem about
   [print] and [parse], and the response path uses no cryptography. *)
Print Assumptions validated_claims_reach_the_client.
