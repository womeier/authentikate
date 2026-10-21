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
                      (write : option bool) : store_ops :=
  MkStore (fun _ => read) (fun _ _ => write).

Definition mock_mail (result : option bool) : email_ops :=
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

Section Service.
Variable cfg : config.

Example signup_created_only_after_matching_write :
  let kv := MkStore (fun _ => Some None)
    (fun key value => Some (andb (bytes_eqb key email)
                                (bytes_eqb value stored_record))) in
  handle (mock_crypto (Some public_enrollment)) kv (mock_mail (Some true))
    cfg 0 RtSignup signup_body = Created.
Proof. vm_compute. reflexivity. Qed.

Example signup_write_refusals :
  forall mail,
  map (fun result => handle (mock_crypto (Some public_enrollment))
    (mock_store (Some None) result) mail cfg 0 RtSignup signup_body)
    [None; Some false] = [Internal; Internal].
Proof. intros. vm_compute. reflexivity. Qed.

Example signup_send_refusals_after_acknowledged_write :
  map (fun result => handle (mock_crypto (Some public_enrollment))
    (mock_store (Some None) (Some true)) (mock_mail result)
    cfg 0 RtSignup signup_body)
    [None; Some false] = [Internal; Internal].
Proof. vm_compute. reflexivity. Qed.

(* The second store models a later read of the persisted record, not an
   atomicity or read-after-write guarantee of the pure operations. *)
Example signup_send_failure_then_retry_conflicts :
  map (fun result =>
    (status (handle (mock_crypto (Some public_enrollment))
      (mock_store (Some None) (Some true)) (mock_mail result)
      cfg 0 RtSignup signup_body),
     status (handle (mock_crypto (Some public_enrollment))
      (mock_store (Some (Some stored_record)) (Some true)) (mock_mail result)
      cfg 0 RtSignup signup_body)))
    [None; Some false] = [(500, 409); (500, 409)].
Proof. vm_compute. reflexivity. Qed.

Example signup_enrollment_refusals :
  map (fun enrolled => handle (mock_crypto enrolled)
    (mock_store (Some None) (Some true)) (mock_mail (Some true))
    cfg 0 RtSignup signup_body)
    [None; Some (lit "{}"%string)] = [Internal; Internal].
Proof. vm_compute. reflexivity. Qed.

Example signup_store_unavailable :
  handle (mock_crypto (Some public_enrollment))
    (mock_store None (Some true)) (mock_mail (Some true))
    cfg 0 RtSignup signup_body = Internal.
Proof. vm_compute. reflexivity. Qed.

(* Even an enrollment refusal and a set refusal cannot turn an existing
   account into a 500: neither result is needed on the conflict path. *)
Example signup_existing_account :
  handle (mock_crypto None)
    (mock_store (Some (Some stored_record)) None) (mock_mail None)
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
  handle (mock_crypto None) (mock_store None None) (mock_mail None) cfg 0 RtSignup
    (lit "{}"%string) = BadRequest.
Proof. vm_compute. reflexivity. Qed.

End Service.

(* Exact matching of all four public arguments also rejects password-bearing
   subjects or bodies.  Both senders exercise the appended config field. *)
Example signup_sends_configured_welcome :
  map (fun sender =>
    let cfg := MkConfig (Key.of_handle 0) (lit "public-key"%string)
      (lit "authentikate"%string) 3600 (lit "dummy-salt"%string)
      (Secret.of_bytes (lit "dummy-tag"%string)) (MkParams 2 19456 2 1 3)
      sender in
    let mail := MkEmail (fun from recipient subject text =>
      Some (andb (bytes_eqb from sender)
        (andb (bytes_eqb recipient email)
          (andb (bytes_eqb subject (lit "Welcome to Authentikate"%string))
            (bytes_eqb text
              (lit "Your Authentikate account has been created."%string)))))) in
    handle (mock_crypto (Some public_enrollment))
      (mock_store (Some None) (Some true)) mail cfg 0 RtSignup signup_body)
    [lit "welcome@example.test"%string; lit "accounts@example.test"%string] =
    [Created; Created].
Proof. vm_compute. reflexivity. Qed.

Example signup_statuses : map status [Created; Conflict; Internal] = [201; 409; 500].
Proof. reflexivity. Qed.

Example signup_created_has_no_token : render Created = lit "{}"%string.
Proof. reflexivity. Qed.
