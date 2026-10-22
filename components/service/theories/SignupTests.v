(* Pure signup regressions. Secret values are only passed to mocks that ignore
   them; the tests do not unfold or inspect the opaque Secret.t. *)
From Stdlib Require Import List NArith Strings.Byte Strings.String.
From Authentikate Require Import Bytes Json Crypto Store Api.
Import ListNotations.
Local Open Scope N_scope.

Definition email := lit "user@example.test"%string.
Definition signup_body :=
  lit "{""email"":""user@example.test"",""password"":""password""}"%string.
Definition public_enrollment := lit
  "{""salt"":""c2FsdA"",""tag"":""dGFn"",""algorithm"":2,""memory_kib"":19456,""iterations"":2,""parallelism"":1,""tag_length"":3}"%string.
Definition stored_record := lit
  "{""email"":""user@example.test"",""salt"":""c2FsdA"",""tag"":""dGFn"",""algorithm"":2,""memory_kib"":19456,""iterations"":2,""parallelism"":1,""tag_length"":3}"%string.

Definition mock_crypto (enrolled : option bytes) : crypto_ops :=
  MkOps (fun _ _ _ _ => None) (fun _ => enrolled)
        (fun _ _ => None) (fun _ _ _ => None).

Definition mock_store (read : option (option bytes))
                      (create : option bool) : store_ops :=
  MkStore (fun _ => read) (fun _ _ => create).

Definition mock_mail (result : bool) : email_ops :=
  MkEmail (fun _ _ _ _ => result).

Example signup_schema :
  parse_request RtSignup signup_body =
    Signup email (Secret.of_bytes (lit "password"%string)).
Proof. vm_compute. reflexivity. Qed.

Example signup_requires_password :
  parse_request RtSignup (lit "{""email"":""user@example.test""}"%string) = Malformed.
Proof. vm_compute. reflexivity. Qed.

Example enrollment_adds_email :
  Store.enrollment_record email public_enrollment = Some stored_record.
Proof. vm_compute. reflexivity. Qed.

Example enrollment_rejects_existing_email :
  Store.enrollment_record email stored_record = None.
Proof. vm_compute. reflexivity. Qed.

Example enrollment_rejects_invalid :
  map (Store.enrollment_record email)
    [lit "[]"%string; lit "{}"%string;
     lit "{""salt"":""+invalid"",""tag"":""dGFn"",""algorithm"":2,""memory_kib"":1,""iterations"":1,""parallelism"":1,""tag_length"":3}"%string] =
    [None; None; None].
Proof. vm_compute. reflexivity. Qed.

(* Reject quote injection even for callers bypassing [parse_request]. *)
Example enrollment_rejects_quote_injection :
  Store.enrollment_record (lit "user"",""extra"":""value"%string)
    public_enrollment = None.
Proof. vm_compute. reflexivity. Qed.

Example enrollment_rejects_unsafe_email_bytes :
  map (fun b => Store.enrollment_record (BS.String (byte_of_N b) BS.EmptyString)
                public_enrollment)
    [0; 31; 34; 92; 127; 128; 255] =
    [None; None; None; None; None; None; None].
Proof. vm_compute. reflexivity. Qed.

Example enrollment_accepts_safe_email_edges :
  map (fun e => Store.enrollment_record e public_enrollment)
    [BS.EmptyString; lit " ~"%string] =
  map (fun e => Some (Json.print (Store.record_json e
    (MkPublic (lit "c2FsdA"%string) (lit "dGFn"%string)
      (MkParams 2 19456 2 1 3))))) [BS.EmptyString; lit " ~"%string].
Proof. vm_compute. reflexivity. Qed.

Definition enrollment_fixture (salt tag : bytes) (p : argon2_params)
    (extra : list (bytes * json)) : bytes :=
  Json.print (JObj
    ([(lit "salt"%string, JStr salt); (lit "tag"%string, JStr tag);
      (lit "algorithm"%string, JNum (ap_algorithm p));
      (lit "memory_kib"%string, JNum (ap_memory_kib p));
      (lit "iterations"%string, JNum (ap_iterations p));
      (lit "parallelism"%string, JNum (ap_parallelism p));
      (lit "tag_length"%string, JNum (ap_tag_length p))] ++ extra)).

Example enrollment_checks_every_u32_bound :
  map (fun p => Store.enrollment_record email
    (enrollment_fixture (lit "c2FsdA"%string) (lit "dGFn"%string) p []))
    [MkParams 4294967296 1 1 1 1; MkParams 1 4294967296 1 1 1;
     MkParams 1 1 4294967296 1 1; MkParams 1 1 1 4294967296 1;
     MkParams 1 1 1 1 4294967296] = [None; None; None; None; None].
Proof. vm_compute. reflexivity. Qed.

Example enrollment_preserves_u32_edges_and_ignores_extra_fields :
  map (fun n =>
    let p := MkParams n n n n n in
    Store.enrollment_record email
      (enrollment_fixture (lit "c2FsdA"%string) (lit "dGFn"%string) p
        [(lit "ignored"%string, JObj [(lit "nested"%string, JBool true)])]))
    [0; 4294967295] =
  map (fun n => Some (Json.print (Store.record_json email
    (MkPublic (lit "c2FsdA"%string) (lit "dGFn"%string)
      (MkParams n n n n n))))) [0; 4294967295].
Proof. vm_compute. reflexivity. Qed.

Example enrollment_rejects_provider_email_of_any_type :
  map (fun value => Store.enrollment_record email
    (enrollment_fixture (lit "c2FsdA"%string) (lit "dGFn"%string)
      (MkParams 2 19456 2 1 3) [(lit "email"%string, value)]))
    [JStr BS.EmptyString; JNum 0; JBool false; JObj []] =
    [None; None; None; None].
Proof. vm_compute. reflexivity. Qed.

Example enrollment_checks_both_base64_fields :
  map (fun pair => Store.enrollment_record email
    (enrollment_fixture (fst pair) (snd pair) (MkParams 2 19456 2 1 3) []))
    [(lit "+invalid"%string, lit "dGFn"%string);
     (lit "c2FsdA"%string, lit "+invalid"%string);
     (lit "A"%string, lit "dGFn"%string);
     (lit "c2FsdA"%string, lit "A"%string)] = [None; None; None; None].
Proof. vm_compute. reflexivity. Qed.

(* No new salt/tag length policy: even empty decoded fields retain the old
   behavior, and successful validation stores their original encoded bytes. *)
Example enrollment_preserves_decodable_base64_bytes :
  map (fun pair => Store.enrollment_record email
    (enrollment_fixture (fst pair) (snd pair) (MkParams 2 19456 2 1 3) []))
    [(BS.EmptyString, BS.EmptyString); (lit "_w"%string, lit "-w"%string)] =
  map (fun pair => Some (Json.print (Store.record_json email
    (MkPublic (fst pair) (snd pair) (MkParams 2 19456 2 1 3)))))
    [(BS.EmptyString, BS.EmptyString); (lit "_w"%string, lit "-w"%string)].
Proof. vm_compute. reflexivity. Qed.

Section Service.
Variable cfg : config.

Example signup_created_only_after_matching_write :
  let kv := MkStore (fun _ => Some None)
    (fun key value => Some (andb (bytes_eqb key email)
                                (bytes_eqb value stored_record))) in
  handle (mock_crypto (Some public_enrollment)) kv (mock_mail true)
    cfg 0 RtSignup signup_body = Created.
Proof. vm_compute. reflexivity. Qed.

(* The two ways a create can fail to create, and they are not the same
   answer.  [None] is the store refusing, which is a 500.  [Some false] is
   another caller already holding the key -- the race the read above cannot
   see -- and that is a conflict, the same answer the read would have given a
   moment later. *)
Example signup_create_refusals :
  forall mail,
  map (fun result => handle (mock_crypto (Some public_enrollment))
    (mock_store (Some None) result) mail cfg 0 RtSignup signup_body)
    [None; Some false] = [Internal; Conflict].
Proof. intros. vm_compute. reflexivity. Qed.

Example signup_send_refusal_after_acknowledged_write :
  handle (mock_crypto (Some public_enrollment))
    (mock_store (Some None) (Some true)) (mock_mail false)
    cfg 0 RtSignup signup_body = Internal.
Proof. vm_compute. reflexivity. Qed.

(* The second store models a later read of the persisted record, not an
   atomicity or read-after-write guarantee of the pure operations. *)
Example signup_send_failure_then_retry_conflicts :
  (status (handle (mock_crypto (Some public_enrollment))
     (mock_store (Some None) (Some true)) (mock_mail false)
     cfg 0 RtSignup signup_body),
   status (handle (mock_crypto (Some public_enrollment))
     (mock_store (Some (Some stored_record)) (Some true)) (mock_mail false)
     cfg 0 RtSignup signup_body)) = (500, 409).
Proof. vm_compute. reflexivity. Qed.

Example signup_enrollment_refusals :
  map (fun enrolled => handle (mock_crypto enrolled)
    (mock_store (Some None) (Some true)) (mock_mail true)
    cfg 0 RtSignup signup_body)
    [None; Some (lit "{}"%string)] = [Internal; Internal].
Proof. vm_compute. reflexivity. Qed.

Example signup_store_unavailable :
  handle (mock_crypto (Some public_enrollment))
    (mock_store None (Some true)) (mock_mail true)
    cfg 0 RtSignup signup_body = Internal.
Proof. vm_compute. reflexivity. Qed.

(* Even an enrollment refusal and a set refusal cannot turn an existing
   account into a 500: neither result is needed on the conflict path. *)
Example signup_existing_account :
  handle (mock_crypto None)
    (mock_store (Some (Some stored_record)) None) (mock_mail false)
    cfg 0 RtSignup signup_body = Conflict.
Proof. vm_compute. reflexivity. Qed.

(* Arbitrary enrollment/write functions remain unused for any existing key,
   including records that login would treat as absent. *)
Example signup_existing_corrupt_record :
  forall ops write mail,
    handle ops (MkStore (fun _ => Some (Some (lit "not JSON"%string))) write)
      mail cfg 0 RtSignup signup_body = Conflict.
Proof. intros. vm_compute. reflexivity. Qed.

Example signup_existing_mismatched_record :
  forall ops write mail,
    let foreign_record := Json.print (JObj
      [(lit "email"%string, JStr (lit "other@example.test"%string));
       (lit "salt"%string, JStr (lit "c2FsdA"%string));
       (lit "tag"%string, JStr (lit "dGFn"%string));
       (lit "algorithm"%string, JNum 2);
       (lit "memory_kib"%string, JNum 19456);
       (lit "iterations"%string, JNum 2);
       (lit "parallelism"%string, JNum 1);
       (lit "tag_length"%string, JNum 3)]) in
    handle ops (MkStore (fun _ => Some (Some foreign_record)) write)
      mail cfg 0 RtSignup signup_body = Conflict.
Proof. intros. vm_compute. reflexivity. Qed.

Example signup_malformed :
  handle (mock_crypto None) (mock_store None None) (mock_mail false) cfg 0 RtSignup
    (lit "{}"%string) = BadRequest.
Proof. vm_compute. reflexivity. Qed.

End Service.

(* Exact matching of all four public arguments also rejects password-bearing
   subjects or bodies.  Both senders exercise the appended config field. *)
Example signup_sends_configured_welcome :
  map (fun sender =>
    let cfg := MkConfig (Key.of_handle 0)
      (lit "authentikate"%string) 3600 (lit "dummy-salt"%string)
      (Secret.of_bytes (lit "dummy-tag"%string)) (MkParams 2 19456 2 1 3)
      sender in
    let mail := MkEmail (fun from recipient subject text =>
      andb (bytes_eqb from sender)
        (andb (bytes_eqb recipient email)
          (andb (bytes_eqb subject (lit "Welcome to Authentikate"%string))
            (bytes_eqb text
              (lit "Your Authentikate account has been created."%string))))) in
    handle (mock_crypto (Some public_enrollment))
      (mock_store (Some None) (Some true)) mail cfg 0 RtSignup signup_body)
    [lit "welcome@example.test"%string; lit "accounts@example.test"%string] =
    [Created; Created].
Proof. vm_compute. reflexivity. Qed.

Example signup_statuses : map status [Created; Conflict; Internal] = [201; 409; 500].
Proof. reflexivity. Qed.

Example signup_created_has_no_token : render Created = lit "{}"%string.
Proof. reflexivity. Qed.
