(******************************************************************************)
(*  Just enough JSON                                                          *)
(*                                                                            *)
(*  A total parser on bytes, returning an option, and a canonical printer.     *)
(*  Only what the two endpoints and a claim set need: flat and nested objects, *)
(*  strings, non-negative integers, booleans.  No arrays, no null, no floats,  *)
(*  no escapes.                                                               *)
(*                                                                            *)
(*  Deliberate strictness, because a parser is attack surface:                 *)
(*                                                                            *)
(*  - A backslash in a string is rejected rather than interpreted.  A          *)
(*    consequence worth knowing: a password cannot contain a backslash or a    *)
(*    double quote.                                                           *)
(*  - A duplicate key is rejected.  Two spellings of the same claim is how     *)
(*    one reader is made to disagree with another about what a token says.     *)
(*  - A trailing comma is rejected.                                           *)
(*                                                                            *)
(*  Because the parser admits no escapes, a string it returns contains neither *)
(*  of those two characters, and so can be printed back out verbatim.  That is *)
(*  the invariant that lets [print] be total and escape-free: every string it  *)
(*  is ever handed came either from [parse] or from [Base64.encode].          *)
(******************************************************************************)

From Stdlib Require Import List NArith Strings.Byte Strings.String.
From Authentikate Require Import Bytes.

Import ListNotations.
Local Open Scope N_scope.

Inductive json : Set :=
  | JStr  : bytes -> json
  | JNum  : N -> json
  | JBool : bool -> json
  | JObj  : list (bytes * json) -> json.

(* Spelled as codepoints rather than as byte literals: [""""%byte] is harder
   to read than it is to get wrong. *)
Definition quote     : byte := byte_of_N 34.
Definition backslash : byte := byte_of_N 92.
Definition lbrace    : byte := byte_of_N 123.
Definition rbrace    : byte := byte_of_N 125.
Definition colon     : byte := byte_of_N 58.
Definition comma     : byte := byte_of_N 44.

(* ---- printing ------------------------------------------------------------ *)

Definition print_string (s : bytes) : bytes :=
  BS.String quote (BS.append s (BS.String quote BS.EmptyString)).

Fixpoint print (j : json) : bytes :=
  match j with
  | JStr s => print_string s
  | JNum n => decimal_of_N n
  | JBool true => lit ("true"%string)
  | JBool false => lit ("false"%string)
  | JObj fields =>
      BS.String lbrace (BS.append
      (let fix go (fs : list (bytes * json)) : bytes :=
         match fs with
         | [] => BS.EmptyString
         | [(k, v)] => BS.append (print_string k) (BS.String colon (print v))
         | (k, v) :: rest =>
              BS.append (print_string k)
                (BS.String colon (BS.append (print v) (BS.String comma (go rest))))
         end
       in go fields) (BS.String rbrace BS.EmptyString))
  end.

(* ---- parsing ------------------------------------------------------------- *)

Definition is_ws (b : byte) : bool :=
  let v := N_of_byte b in
  orb (N.eqb v 32) (orb (N.eqb v 9) (orb (N.eqb v 10) (N.eqb v 13))).

Fixpoint skip_ws (input : bytes) : bytes :=
  match input with
  | BS.String b rest => if is_ws b then skip_ws rest else input
  | BS.EmptyString => BS.EmptyString
  end.

Fixpoint strip_prefix (p input : bytes) : option bytes :=
  match p, input with
  | BS.EmptyString, _ => Some input
  | BS.String pb p', BS.String ib i' => if Byte.eqb pb ib then strip_prefix p' i' else None
  | BS.String _ _, BS.EmptyString => None
  end.

(* The opening quote has already been consumed. *)
Fixpoint parse_string (input acc : bytes) : option (bytes * bytes) :=
  match input with
  | BS.EmptyString => None
  | BS.String b rest =>
      if Byte.eqb b quote then Some (bytes_rev acc, rest)
      else if Byte.eqb b backslash then None
      else parse_string rest (BS.String b acc)
  end.

Fixpoint take_digits (input acc : bytes) : bytes * bytes :=
  match input with
  | BS.String b rest =>
      match digit_val b with
      | Some _ => take_digits rest (BS.String b acc)
      | None => (bytes_rev acc, input)
      end
  | BS.EmptyString => (bytes_rev acc, BS.EmptyString)
  end.

Fixpoint has_key (k : bytes) (fs : list (bytes * json)) : bool :=
  match fs with
  | [] => false
  | (k', _) :: rest => if bytes_eqb k k' then true else has_key k rest
  end.

(* [fuel] bounds the nesting depth; it is the only thing that could recur
   without bound, and 16 is well past a claim set inside a response. *)
Fixpoint parse_value (fuel : nat) (input : bytes) : option (json * bytes) :=
  match fuel with
  | O => None
  | S fuel' =>
      match skip_ws input with
      | BS.EmptyString => None
      | BS.String b rest =>
          if Byte.eqb b quote then
            match parse_string rest BS.EmptyString with
            | Some (s, rest') => Some (JStr s, rest')
            | None => None
            end
          else if Byte.eqb b lbrace then
            match parse_fields fuel' rest [] with
            | Some (fs, rest') => Some (JObj fs, rest')
            | None => None
            end
          else
            match strip_prefix (lit ("true"%string)) (BS.String b rest) with
            | Some rest' => Some (JBool true, rest')
            | None =>
                match strip_prefix (lit ("false"%string)) (BS.String b rest) with
                | Some rest' => Some (JBool false, rest')
                | None =>
                    match digit_val b with
                    | Some _ =>
                        match take_digits (BS.String b rest) BS.EmptyString with
                        | (ds, rest') =>
                            match N_of_decimal ds with
                            | Some n => Some (JNum n, rest')
                            | None => None
                            end
                        end
                    | None => None
                    end
                end
            end
      end
  end

with parse_fields (fuel : nat) (input : bytes) (acc : list (bytes * json))
  : option (list (bytes * json) * bytes) :=
  match fuel with
  | O => None
  | S fuel' =>
      match skip_ws input with
      | BS.EmptyString => None
      | BS.String b rest =>
          if Byte.eqb b rbrace then Some (rev acc, rest)
          else if Byte.eqb b quote then
            match parse_string rest BS.EmptyString with
            | Some (k, r1) =>
                if has_key k acc then None  (* duplicate key *)
                else
                  match skip_ws r1 with
                  | BS.EmptyString => None
                  | BS.String c r2 =>
                      if Byte.eqb c colon then
                        match parse_value fuel' r2 with
                        | Some (v, r3) =>
                            match skip_ws r3 with
                            | BS.EmptyString => None
                            | BS.String d r4 =>
                                if Byte.eqb d comma then
                                  (* a key must follow: no trailing comma *)
                                  match skip_ws r4 with
                                  | BS.EmptyString => None
                                  | BS.String e _ =>
                                      if Byte.eqb e quote
                                      then parse_fields fuel' r4 ((k, v) :: acc)
                                      else None
                                  end
                                else if Byte.eqb d rbrace
                                then Some (rev ((k, v) :: acc), r4)
                                else None
                            end
                        | None => None
                        end
                      else None
                  end
            | None => None
            end
          else None
      end
  end.

(* Trailing bytes after the value are a parse failure, not something to
   ignore: a request body with a second object in it is not a request. *)
Definition parse (input : bytes) : option json :=
  match parse_value 16 input with
  | Some (j, rest) =>
      match skip_ws rest with
      | BS.EmptyString => Some j
      | _ => None
      end
  | None => None
  end.

(* ---- reading fields ------------------------------------------------------ *)

Fixpoint field (k : bytes) (fs : list (bytes * json)) : option json :=
  match fs with
  | [] => None
  | (k', v) :: rest => if bytes_eqb k k' then Some v else field k rest
  end.

Definition get (k : bytes) (j : json) : option json :=
  match j with
  | JObj fs => field k fs
  | _ => None
  end.

Definition get_str (k : bytes) (j : json) : option bytes :=
  match get k j with
  | Some (JStr s) => Some s
  | _ => None
  end.

Definition get_num (k : bytes) (j : json) : option N :=
  match get k j with
  | Some (JNum n) => Some n
  | _ => None
  end.
