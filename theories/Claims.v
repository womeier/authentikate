(******************************************************************************)
(*  Claims                                                                    *)
(*                                                                            *)
(*  The four claims this service mints and reads.  [iat] and [exp] are [N]:    *)
(*  CertiCoq represents [nat] in unary, so a timestamp as a [nat] would be a   *)
(*  heap cell per second since 1970.                                          *)
(******************************************************************************)

From Stdlib Require Import List NArith Strings.Byte Strings.String.
From Authentikate Require Import Bytes Json.

Import ListNotations.
Local Open Scope N_scope.

Record claims := MkClaims {
  c_sub : bytes;
  c_iss : bytes;
  c_iat : N;
  c_exp : N
}.

Definition to_json (c : claims) : json :=
  JObj [ (lit ("sub"%string), JStr (c_sub c));
         (lit ("iss"%string), JStr (c_iss c));
         (lit ("iat"%string), JNum (c_iat c));
         (lit ("exp"%string), JNum (c_exp c)) ].

(* Every claim is required.  A token missing its [exp] is not a token with an
   unbounded lifetime, it is a token we did not mint. *)
Definition of_json (j : json) : option claims :=
  match get_str (lit ("sub"%string)) j, get_str (lit ("iss"%string)) j,
        get_num (lit ("iat"%string)) j, get_num (lit ("exp"%string)) j with
  | Some sub, Some iss, Some iat, Some exp => Some (MkClaims sub iss iat exp)
  | _, _, _, _ => None
  end.

(* [exp] is exclusive: a token expires at the instant it names. *)
Definition fresh (now : N) (c : claims) : bool := N.ltb now (c_exp c).
