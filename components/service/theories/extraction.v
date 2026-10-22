(* Service extraction.  The pure operations are instantiated only here with
   registered foreign primitives.  See README.md for the build/composition
   pipeline. *)

From Stdlib Require Import List NArith Strings.Byte Strings.String.
From Authentikate Require Import Bytes Base64 Json Crypto Claims Store Jwt Api.
From CertiRocq.Plugin Require Import CertiRocq.

Import ListNotations.

(* Foreign arguments are CertiRocq heap values, not canonical ABI values.
   Registered primitives import env.ffi_* with a leading force argument followed
   by their Rocq arguments as i32s.
   Imports return no Wasm value: adapters publish the
   Rocq result through the shared result global (and update allocation globals
   as needed).  The adapters translate to the component ABI using shared memory.
   Secret.of_bytes is a foreign identity, preserving the source-level seal.
   Secret-dependent computation stays in the crypto components. *)
Axiom ffi_argon2_verify :
  Secret.t -> bytes -> argon2_params -> Secret.t -> option bool.
Axiom ffi_argon2_enroll : Secret.t -> option bytes.
Axiom ffi_hmac_sign : Key.t -> bytes -> option bytes.
Axiom ffi_hmac_verify : Key.t -> bytes -> bytes -> option bool.

(* These signatures abstract effects, not temporal consistency.  Enrollment
   generates fresh randomness, get reads mutable state, and create persists
   it.  No theorem over the pure records establishes read-after-write
   behaviour or atomic uniqueness; the hypotheses in Proofs.v say what is
   needed and the accounts provider must earn them with atomic create-if-absent,
   which is why there is no plain set here -- a set cannot implement create,
   and nothing in this service overwrites a record.
   In particular create must return an inspected result, never unit: Some
   true is this caller creating the pair, Some false is the key already being
   taken, and None is a refusal.  The runtime compiler must retain the call
   and branch on this result. *)
Axiom ffi_kv_get : bytes -> option (option bytes).
Axiom ffi_kv_create : bytes -> bytes -> option bool.

(* Inspect acceptance after persistence to retain the effect: true is accepted,
   false is any refusal, which does not undo the write. *)
Axiom ffi_email_send : bytes -> bytes -> bytes -> bytes -> bool.

(* CertiRocq 6d34b50b's consts_to_values/implement_lazy_force passes apply
   constants to a dummy box before their Rocq arguments.  Explicit arities count
   this extra argument; foreign adapters ignore it.  Otherwise forcing a bare
   primitive calls the import prematurely and shifts its real arguments.
   Include is required by the registration syntax; Wasm needs no C headers. *)
CertiRocq Register [
  ffi_argon2_verify => "ffi_argon2_verify" 5 with tinfo,
  ffi_argon2_enroll => "ffi_argon2_enroll" 2 with tinfo,
  ffi_hmac_sign => "ffi_hmac_sign" 3 with tinfo,
  ffi_hmac_verify => "ffi_hmac_verify" 4 with tinfo,
  ffi_kv_get => "ffi_kv_get" 2 with tinfo,
  ffi_kv_create => "ffi_kv_create" 3 with tinfo,
  ffi_email_send => "ffi_email_send" 5 with tinfo,
  Secret.of_bytes => "ffi_secret_of_bytes" 2
]
Include [ ].

Definition ffi_ops : crypto_ops :=
  MkOps ffi_argon2_verify ffi_argon2_enroll ffi_hmac_sign ffi_hmac_verify.

Definition ffi_kv : store_ops := MkStore ffi_kv_get ffi_kv_create.

Definition ffi_mail : email_ops := MkEmail ffi_email_send.

(* Return status and body so the host only moves bytes. *)
Definition serve (cfg : config) (now : N) (r : route) (body : bytes)
  : N * bytes :=
  let resp := handle ffi_ops ffi_kv ffi_mail cfg now r body in
  (status resp, render resp).

Definition login (cfg : config) (now : N) (body : bytes) : N * bytes :=
  serve cfg now RtLogin body.

(* Validation does not reach the store imports and survives a store outage. *)
Definition validate (cfg : config) (now : N) (body : bytes) : N * bytes :=
  serve cfg now RtValidate body.

Definition signup (cfg : config) (now : N) (body : bytes) : N * bytes :=
  serve cfg now RtSignup body.

Record api : Set := MkApi {
  api_login : config -> N -> bytes -> N * bytes;
  api_validate : config -> N -> bytes -> N * bytes;
  api_signup : config -> N -> bytes -> N * bytes
}.

Definition authentikate_api : api :=
  {| api_login := login; api_validate := validate; api_signup := signup |}.

CertiRocq Compile Wasm
  --output "../../build/Authentikate.extraction.authentikate_api"
  authentikate_api.
