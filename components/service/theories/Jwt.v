(******************************************************************************)
(*  The compact JWS                                                           *)
(*                                                                            *)
(*  Three base64url segments joined by dots.  Two decisions worth naming:      *)
(*                                                                            *)
(*  - The algorithm is not read from the header.  [verify] compares the        *)
(*    token's header segment against the one and only header this service      *)
(*    mints, so [alg: none] and [alg: EdDSA] are rejected because they are     *)
(*    not that header, not because a check caught them.  This is stricter      *)
(*    than RFC 7515, which would allow the two fields in either order; since   *)
(*    we are the only issuer, strictness costs nothing and removes the whole   *)
(*    family of algorithm-confusion attacks by construction.                   *)
(*                                                                            *)
(*  - The payload is parsed only after the signature verifies.  Untrusted      *)
(*    JSON should not reach the parser on the strength of an unchecked token.  *)
(******************************************************************************)

From Stdlib Require Import List NArith Strings.Byte Strings.String.
From Authentikate Require Import Bytes Base64 Json Crypto Claims.

Import ListNotations.

Definition header : json :=
  JObj [ (lit ("alg"%string), JStr (lit ("HS256"%string)));
         (lit ("typ"%string), JStr (lit ("JWT"%string))) ].

(* Compared in encoded form, which is canonical because [Base64.decode]
   rejects a non-canonical tail: there is exactly one spelling of it. *)
Definition header_b64 : bytes := Base64.encode (Json.print header).

Definition signing_input (h p : bytes) : bytes := BS.append h (BS.String dot p).

Definition sign (ops : crypto_ops) (k : Key.t) (c : claims) : option bytes :=
  let p := Base64.encode (Json.print (Claims.to_json c)) in
  let si := signing_input header_b64 p in
  match hmac_sign ops k si with
  | Some sg => Some (BS.append si (BS.String dot (Base64.encode sg)))
  | None => None
  end.

Definition verify (ops : crypto_ops) (key : Key.t) (token : bytes) : option claims :=
  match split_on dot token with
  | [h; p; s] =>
      if bytes_eqb h header_b64 then
        match Base64.decode s with
        | Some sg =>
            match hmac_verify ops key (signing_input h p) sg with
            | Some true =>
                match Base64.decode p with
                | Some pb =>
                    match Json.parse pb with
                    | Some j => Claims.of_json j
                    | None => None
                    end
                | None => None
                end
            | _ => None  (* [Some false] is a bad signature, [None] a bad input *)
            end
        | None => None
        end
      else None
  | _ => None  (* a compact JWS has exactly three segments *)
  end.
