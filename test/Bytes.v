(* Regression checks for the shared MetaRocq bytestring representation.
   Checked by make alongside the service proofs. *)
From Stdlib Require Import List NArith Strings.Byte Strings.String.
From Authentikate Require Import Bytes Base64 Json JsonProofs.
Import ListNotations.

Example split_empty : split_on dot BS.EmptyString = [BS.EmptyString].
Proof. reflexivity. Qed.

Example split_empty_segments :
  split_on dot (lit ".a.."%string) =
    [BS.EmptyString; lit "a"%string; BS.EmptyString; BS.EmptyString].
Proof. reflexivity. Qed.

Example join_empty_segments :
  join dot [BS.EmptyString; lit "a"%string; BS.EmptyString; BS.EmptyString] =
    lit ".a.."%string.
Proof. reflexivity. Qed.

Example reverse_binary :
  bytes_rev (BS.String x00 (BS.String xff BS.EmptyString)) =
    BS.String xff (BS.String x00 BS.EmptyString).
Proof. reflexivity. Qed.

Example decimal_zero : decimal_of_N 0 = lit "0"%string.
Proof. reflexivity. Qed.

Example decimal_timestamp :
  N_of_decimal (decimal_of_N 1792454400) = Some 1792454400%N.
Proof. vm_compute. reflexivity. Qed.

Example parse_empty_string :
  Json.parse (print_string BS.EmptyString) = Some (JStr BS.EmptyString).
Proof. reflexivity. Qed.

Example parse_nested_object :
  let j := JObj [(lit "claims"%string,
    JObj [(lit "sub"%string, JStr (lit "user"%string));
          (lit "exp"%string, JNum 1792454400)])] in
  Json.parse (Json.print j) = Some j.
Proof. vm_compute. reflexivity. Qed.

Example reject_duplicate_key :
  Json.parse (Json.print (JObj
    [(lit "a"%string, JBool true); (lit "a"%string, JBool false)])) = None.
Proof. reflexivity. Qed.

Example reject_trailing_comma : Json.parse (lit "{ ""a"": true, }"%string) = None.
Proof. reflexivity. Qed.

Example reject_backslash :
  parse_string (BS.String backslash (BS.String quote BS.EmptyString)) BS.EmptyString = None.
Proof. reflexivity. Qed.

Example base64_vectors :
  map Base64.encode (map lit
    [""; "f"; "fo"; "foo"; "foob"; "fooba"; "foobar"]%string) =
  map lit [""; "Zg"; "Zm8"; "Zm9v"; "Zm9vYg"; "Zm9vYmE"; "Zm9vYmFy"]%string.
Proof. vm_compute. reflexivity. Qed.

Example base64_url_alphabet :
  Base64.encode (BS.String xfb (BS.String xff BS.EmptyString)) = lit "-_8"%string.
Proof. vm_compute. reflexivity. Qed.

Example base64_decode_binary :
  Base64.decode (lit "-_8"%string) =
  Some (BS.String xfb (BS.String xff BS.EmptyString)).
Proof. vm_compute. reflexivity. Qed.

Example base64_reject_malformed :
  map (fun s => Base64.decode (lit s))
    ["Z"; "Zg=="; "+/8"; "Zg "; "Zh"; "Zm9"]%string =
  [None; None; None; None; None; None].
Proof. vm_compute. reflexivity. Qed.
