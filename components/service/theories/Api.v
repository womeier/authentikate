(******************************************************************************)
(*  The service                                                               *)
(*                                                                            *)
(*  [handle] is the whole thing: a function from a route, a body and a clock    *)
(*  reading to a response.  The clock is an argument rather than an import,     *)
(*  which keeps it pure and makes the [exp] reasoning trivial.                  *)
(*                                                                            *)
(*  Crypto, storage and email arrive as records of operations ([crypto_ops],   *)
(*  [store_ops], [email_ops]) rather than as axioms, so theorems in Proofs.v    *)
(*  universally quantified over them and the global context stays closed.      *)
(*  What that buys is worth being precise about: the theorems say whatever     *)
(*  the store returned, it decoded and verified, which is true of the           *)
(*  running system.  They do not say the store returned the record that was    *)
(*  written for that email -- nothing provable can, since another writer may   *)
(*  have been there first.                                                    *)
(******************************************************************************)

From Stdlib Require Import List NArith Strings.Byte Strings.String.
From Authentikate Require Import Bytes Base64 Json Crypto Claims Store Jwt.

Import ListNotations.
Local Open Scope N_scope.

Inductive route := RtLogin | RtValidate | RtUnknown | RtSignup.

Inductive request :=
  | Login : bytes -> Secret.t -> request
  | Validate : bytes -> request
  | Malformed : request
  | Signup : bytes -> Secret.t -> request.

Inductive response :=
  | Token : bytes -> response
  | Validity : bool -> option claims -> response
  | Unauthorized : response
  | BadRequest : response
  | Internal : response
  | Created : response
  | Conflict : response.

(* Everything the host installs at instantiation. *)
Record config := MkConfig {
  cfg_key : Key.t;          (* handle to the signing key, held by the component *)
  cfg_iss : bytes;
  cfg_ttl : N;
  (* A salt and tag to hash against when the email is unknown, so that a
     login for a nonexistent user costs the same as one for a real user with
     the wrong password.  Without this the uniform 401 below is undone by a
     microsecond-scale user-enumeration oracle. *)
  cfg_dummy_salt : bytes;
  cfg_dummy_tag : Secret.t;
  (* And the cost parameters to hash the dummy under.  These have to be the
     parameters real records use, or the dummy path is distinguishable by how
     long it takes -- which is the oracle [cfg_dummy_tag] exists to close.
     Note what that means once records start carrying different generations of
     parameters: the dummy can only match one of them, so a login's duration
     reveals which generation an account belongs to, and accounts stored under
     a since-retired recommendation are distinguishable from absent ones.  The
     fix is a migration that re-hashes on login rather than a cleverer dummy,
     and re-hashing on login is not implemented by the signup write path. *)
  cfg_dummy_params : argon2_params;
  cfg_email_from : bytes
}.

Record email_ops := MkEmail {
  (* Sender, recipient, subject, text; true means accepted, false any refusal.
     Acceptance is not a delivery guarantee. *)
  send_email : bytes -> bytes -> bytes -> bytes -> bool
}.

Definition parse_request (r : route) (body : bytes) : request :=
  match r with
  | RtLogin | RtSignup =>
      match Json.parse body with
      | Some j =>
          match Json.get_str (lit ("email"%string)) j,
                Json.get_str (lit ("password"%string)) j with
          | Some e, Some p =>
              match r with
              | RtSignup => Signup e (Secret.of_bytes p)
              | _ => Login e (Secret.of_bytes p)
              end
          | _, _ => Malformed
          end
      | None => Malformed
      end
  | RtValidate =>
      match Json.parse body with
      | Some j =>
          match Json.get_str (lit ("token"%string)) j with
          | Some t => Validate t
          | None => Malformed
          end
      | None => Malformed
      end
  | RtUnknown => Malformed
  end.

(* The lookup result picks which salt, parameters and tag to hash against, but
   the hash runs either way, and the [found] test comes after it: a missing
   account and a wrong password take the same path through the expensive part.
   Factored out of [handle] so that this -- the only place where the two cases
   must stay indistinguishable -- can be read, and reasoned about, on its own. *)
Definition login_check (ops : crypto_ops) (cfg : config) (found : option user)
                       (email : bytes) (now : N) (password : Secret.t) : response :=
  let salt := match found with
              | Some u => u_salt u
              | None => cfg_dummy_salt cfg
              end in
  let params := match found with
                | Some u => u_params u
                | None => cfg_dummy_params cfg
                end in
  let tag := match found with
             | Some u => u_tag u
             | None => cfg_dummy_tag cfg
             end in
  match argon2_verify ops password salt params tag, found with
  | Some true, Some _ =>
      match Jwt.sign ops (cfg_key cfg)
              (MkClaims email (cfg_iss cfg) now (now + cfg_ttl cfg)) with
      | Some t => Token t
      | None => Internal  (* the component refused; not the caller's fault *)
      end
  | _, _ => Unauthorized
  end.

Definition handle (ops : crypto_ops) (kv : store_ops) (mail : email_ops)
                  (cfg : config) (now : N)
                  (r : route) (body : bytes) : response :=
  match parse_request r body with
  | Malformed => BadRequest
  | Signup email password =>
      (* The read first, and it decides nothing.  Any existing key conflicts,
         even if its record cannot be decoded, and answering here saves an
         Argon2 for a signup that cannot succeed -- which is the only reason
         it is here, since enumeration is already disclosed by the 409.  The
         write below is what the account's uniqueness rests on. *)
      match kv_get kv email with
      | Some (Some _) => Conflict
      | None => Internal
      | Some None =>
          match argon2_enroll ops password with
          | None => Internal
          | Some public_json =>
              match Store.enrollment_record email public_json with
              | None => Internal
              | Some v =>
                  (* Create, not set: [Some false] is another caller holding
                     the key, which is a conflict and not a failure, and is
                     the answer that closes the get-then-set race.  The read
                     above may have said absent a moment ago; this is the
                     answer that counts. *)
                  match kv_create kv email v with
                  | Some true =>
                      (* A send refusal is a 500 after persistence, not a
                         rollback: a retry finding this key conflicts. *)
                      match send_email mail (cfg_email_from cfg) email
                        (lit ("Welcome to Authentikate"%string))
                        (lit ("Your Authentikate account has been created."%string)) with
                      | true => Created
                      | false => Internal
                      end
                  | Some false => Conflict
                  | None => Internal
                  end
              end
          end
      end
  | Login email password =>
      match Store.stored kv email with
      (* The store refusing is the one case that skips the hash, and it is
         allowed to: a 500 says "we do not know", which is no evidence either
         way about whether the account exists. *)
      | Unavailable => Internal
      | Found u => login_check ops cfg (Some u) email now password
      | Absent => login_check ops cfg None email now password
      end
  | Validate token =>
      (* No store read: a token carries its own claims and its own signature,
         so validating one is arithmetic.  Which is the property that lets the
         validate path scale past the store, and the reason revocation is not
         expressible here. *)
      match Jwt.verify ops (cfg_key cfg) token with
      | Some c =>
          if andb (Claims.fresh now c) (bytes_eqb (c_iss c) (cfg_iss cfg))
          then Validity true (Some c)
          else Validity false None
      | None => Validity false None
      end
  end.

(* ---- the wire ------------------------------------------------------------ *)

Definition status (r : response) : N :=
  match r with
  | Token _ => 200
  | Validity _ _ => 200  (* a bad token is an answer, not a failure *)
  | Unauthorized => 401
  | BadRequest => 400
  | Internal => 500
  | Created => 201
  | Conflict => 409
  end.

(* Claims are echoed only when the token is good; [Validity false] carries
   nothing, so nothing about a rejected token leaks back. *)
Definition render (r : response) : bytes :=
  match r with
  | Token t => Json.print (JObj [(lit ("token"%string), JStr t)])
  | Validity v (Some c) =>
      Json.print (JObj [(lit ("valid"%string), JBool v);
                        (lit ("claims"%string), Claims.to_json c)])
  | Validity v None => Json.print (JObj [(lit ("valid"%string), JBool v)])
  | Unauthorized =>
      Json.print (JObj [(lit ("error"%string), JStr (lit ("unauthorized"%string)))])
  | BadRequest =>
      Json.print (JObj [(lit ("error"%string), JStr (lit ("bad request"%string)))])
  | Internal =>
      Json.print (JObj [(lit ("error"%string), JStr (lit ("internal error"%string)))])
  | Created => Json.print (JObj [])
  | Conflict =>
      Json.print (JObj [(lit ("error"%string), JStr (lit ("conflict"%string)))])
  end.
