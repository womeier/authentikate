(******************************************************************************)
(*  What the JSON round trip is made of                                       *)
(*                                                                            *)
(*  The end-to-end statement in Proofs.v needs [parse (print j) = Some j],    *)
(*  but only for the two shapes that actually occur: a claim set, and the     *)
(*  one-field object a token travels in.  So there is no general round trip   *)
(*  here and no well-formedness predicate over [json] -- restricting to flat  *)
(*  objects whose values are strings and numbers is what keeps the nesting,   *)
(*  the fuel bookkeeping and the trailing-remainder generalisation out of     *)
(*  it.                                                                       *)
(*                                                                            *)
(*  What is proved so far is the bottom of that: decimal numerals round       *)
(*  trip, and [parse_value] reads back a printed string or a printed number.  *)
(*  Both are stated with an arbitrary remainder after the value, because in   *)
(*  an object a value is always followed by a comma or a brace -- that        *)
(*  remainder is what the field-level lemma will thread through.              *)
(*                                                                            *)
(*  Still to come: the field list.  [print]'s object case uses an inner [fix  *)
(*  go] rather than a top-level function, so that needs a [print_fields]      *)
(*  defined here and shown to agree with it, and then an induction carrying   *)
(*  [parse_fields]'s accumulator and the distinctness of the keys it has      *)
(*  already seen.                                                             *)
(******************************************************************************)

From Stdlib Require Import List NArith ZArith Lia Strings.Byte Strings.String.
From Authentikate Require Import Bytes Json.

Import ListNotations.
Local Open Scope N_scope.

(* [lia] knows nothing about [/] and [mod]; this is what tells it. *)
Local Ltac arith := zify; Z.to_euclidean_division_equations; lia.

(* ---- decimal numerals --------------------------------------------------- *)

Lemma digit_val_of_N (r : N) : r < 10 -> digit_val (byte_of_N (48 + r)) = Some r.
Proof.
  intros Hr. unfold digit_val. rewrite N_of_byte_of_N by lia.
  replace (48 <=? 48 + r) with true by (symmetry; apply N.leb_le; lia).
  replace (48 + r <=? 57) with true by (symmetry; apply N.leb_le; lia).
  cbn [andb]. f_equal. lia.
Qed.

Lemma decimal_aux_app : forall fuel n acc,
  decimal_aux fuel n acc = BS.append (decimal_aux fuel n BS.EmptyString) acc.
Proof.
  induction fuel as [| fuel IH]; intros n acc; [reflexivity |].
  cbn [decimal_aux]. cbv zeta.
  destruct (N.ltb n 10); [reflexivity |].
  set (d := byte_of_N (48 + n mod 10)).
  rewrite (IH (n / 10) (BS.String d acc)),
    (IH (n / 10) (BS.String d BS.EmptyString)).
  now rewrite <- bytes_append_assoc.
Qed.

Lemma N_of_decimal_aux_app : forall ds tl a,
  N_of_decimal_aux (BS.append ds tl) a =
  match N_of_decimal_aux ds a with
  | Some v => N_of_decimal_aux tl v
  | None => None
  end.
Proof.
  induction ds as [| b ds IH]; intros tl a; cbn; [reflexivity |].
  destruct (digit_val b); [apply IH | reflexivity].
Qed.

Lemma dec_step (a p q r : N) : (a * p + q) * 10 + r = a * (p * 10) + (10 * q + r).
Proof. ring. Qed.

Lemma decimal_sound : forall fuel n a, n < 10 ^ N.of_nat fuel ->
  N_of_decimal_aux (decimal_aux fuel n BS.EmptyString) a
  = Some (a * 10 ^ N.of_nat (BS.length (decimal_aux fuel n BS.EmptyString)) + n).
Proof.
  induction fuel as [| fuel IH]; intros n a Hn.
  - cbn in Hn |- *. f_equal. lia.
  - cbn [decimal_aux].
    destruct (N.ltb_spec n 10) as [Hlt | Hge].
    + cbn [N_of_decimal_aux BS.length].
      rewrite digit_val_of_N by arith.
      cbn [N_of_decimal_aux]. f_equal.
      replace (n mod 10) with n by arith.
      replace (N.of_nat 1) with 1 by reflexivity. lia.
    + rewrite decimal_aux_app, N_of_decimal_aux_app.
      rewrite IH by (rewrite Nat2N.inj_succ, N.pow_succ_r' in Hn; arith).
      cbn [N_of_decimal_aux].
      rewrite digit_val_of_N by arith.
      cbn [N_of_decimal_aux].
      rewrite bytes_length_append. cbn [BS.length].
      rewrite Nat.add_1_r, Nat2N.inj_succ, N.pow_succ_r'.
      f_equal.
      rewrite N.mul_comm with (n := 10).
      rewrite dec_step. f_equal. arith.
Qed.

(* ---- and the digits they are made of ------------------------------------ *)

Lemma decimal_aux_digits : forall fuel n acc,
  bytes_Forall (fun b => digit_val b <> None) acc ->
  bytes_Forall (fun b => digit_val b <> None) (decimal_aux fuel n acc).
Proof.
  induction fuel as [| fuel IH]; intros n acc Hacc; [exact Hacc |].
  cbn [decimal_aux]. cbv zeta.
  assert (Hd : digit_val (byte_of_N (48 + n mod 10)) <> None).
  { rewrite digit_val_of_N by arith. discriminate. }
  destruct (N.ltb n 10); [ now constructor | apply IH; now constructor ].
Qed.

Lemma decimal_of_N_digits (n : N) :
  bytes_Forall (fun b => digit_val b <> None) (decimal_of_N n).
Proof. apply decimal_aux_digits. constructor. Qed.

(* [fuel] is kept a variable: [decimal_of_N] passes the literal 32, and [cbn]
   on a literal unfolds all thirty-two steps at once. *)
Lemma decimal_aux_nonempty : forall fuel n acc,
  decimal_aux (S fuel) n acc <> BS.EmptyString.
Proof.
  intros fuel n acc. cbn [decimal_aux]. cbv zeta.
  destruct (N.ltb n 10); [discriminate |].
  rewrite decimal_aux_app. intros H.
  apply bytes_append_eq_empty in H as [_ H]. discriminate.
Qed.

Lemma decimal_of_N_nonempty (n : N) : decimal_of_N n <> BS.EmptyString.
Proof. unfold decimal_of_N. apply (decimal_aux_nonempty 31). Qed.

Lemma decimal_round_trip (n : N) :
  n < 10 ^ 32 -> N_of_decimal (decimal_of_N n) = Some n.
Proof.
  intros Hn. unfold N_of_decimal.
  destruct (decimal_of_N n) as [| b l] eqn:E.
  - exfalso. now apply (decimal_of_N_nonempty n).
  - rewrite <- E. unfold decimal_of_N.
    rewrite decimal_sound by (replace (N.of_nat 32) with 32 by reflexivity; exact Hn).
    f_equal; lia.
Qed.

Lemma take_digits_app : forall ds rest acc,
  bytes_Forall (fun b => digit_val b <> None) ds ->
  match rest with BS.EmptyString => True | BS.String b _ => digit_val b = None end ->
  take_digits (BS.append ds rest) acc = (BS.append (bytes_rev acc) ds, rest).
Proof.
  induction ds as [| d ds IH]; intros rest acc Hds Hrest.
  - cbn [BS.append]. rewrite bytes_append_empty.
    destruct rest as [| b tl]; cbn [take_digits]; [reflexivity |].
    now rewrite Hrest.
  - inversion Hds as [| ? ? Hd Hds']; subst.
    cbn [BS.append take_digits].
    destruct (digit_val d) as [v |] eqn:Ed; [| now exfalso].
    rewrite IH by assumption. rewrite bytes_rev_cons.
    now rewrite <- bytes_append_assoc.
Qed.

(* ---- which bytes a digit is not ----------------------------------------- *)

Lemma digit_cases (b : byte) : digit_val b <> None ->
  In b [x30; x31; x32; x33; x34; x35; x36; x37; x38; x39].
Proof.
  intros H.
  destruct b; try (exfalso; apply H; reflexivity); cbn; tauto.
Qed.

Local Ltac by_digit H :=
  apply digit_cases in H;
  repeat (destruct H as [H | H]; [subst; reflexivity |]); contradiction.

Lemma digit_not_ws (b : byte) : digit_val b <> None -> is_ws b = false.
Proof. intros H. by_digit H. Qed.

Lemma digit_not_quote (b : byte) : digit_val b <> None -> Byte.eqb b quote = false.
Proof. intros H. by_digit H. Qed.

Lemma digit_not_lbrace (b : byte) : digit_val b <> None -> Byte.eqb b lbrace = false.
Proof. intros H. by_digit H. Qed.

Lemma digit_not_true (b : byte) (l : bytes) :
  digit_val b <> None -> strip_prefix (lit ("true"%string)) (BS.String b l) = None.
Proof. intros H. by_digit H. Qed.

Lemma digit_not_false (b : byte) (l : bytes) :
  digit_val b <> None -> strip_prefix (lit ("false"%string)) (BS.String b l) = None.
Proof. intros H. by_digit H. Qed.

(* ---- strings ------------------------------------------------------------ *)

Definition ok_string (s : bytes) : Prop :=
  ~ bytes_In quote s /\ ~ bytes_In backslash s.

Lemma skip_ws_head (b : byte) (l : bytes) :
  is_ws b = false -> skip_ws (BS.String b l) = BS.String b l.
Proof. intros H. cbn [skip_ws]. now rewrite H. Qed.

Lemma parse_string_print : forall s acc rest,
  ok_string s -> parse_string (BS.append s (BS.String quote rest)) acc =
    Some (BS.append (bytes_rev acc) s, rest).
Proof.
  induction s as [| b s IH]; intros acc rest [Hq Hb].
  - cbn [BS.append parse_string]. rewrite (byte_dec_lb (@Logic.eq_refl byte quote)).
    now rewrite bytes_append_empty.
  - cbn [BS.append parse_string].
    rewrite byte_eqb_false by (intro; subst; apply Hq; now left).
    rewrite byte_eqb_false by (intro; subst; apply Hb; now left).
    rewrite IH by (split; intro; [apply Hq | apply Hb]; now right).
    rewrite bytes_rev_cons. now rewrite <- bytes_append_assoc.
Qed.

Lemma parse_value_str : forall fuel s rest,
  ok_string s -> parse_value (S fuel) (BS.append (print_string s) rest) = Some (JStr s, rest).
Proof.
  intros fuel s rest Hs.
  assert (E : BS.append (print_string s) rest =
    BS.String quote (BS.append s (BS.String quote rest))).
  { unfold print_string. cbn [BS.append]. now rewrite <- bytes_append_assoc. }
  rewrite E. cbn -[parse_string].
  now rewrite parse_string_print by exact Hs.
Qed.

Definition no_digit_next (rest : bytes) : Prop :=
  match rest with BS.EmptyString => True | BS.String b _ => digit_val b = None end.

Lemma parse_value_num : forall fuel n rest,
  n < 10 ^ 32 -> no_digit_next rest ->
  parse_value (S fuel) (BS.append (decimal_of_N n) rest) = Some (JNum n, rest).
Proof.
  intros fuel n rest Hn Hrest.
  pose proof (decimal_of_N_digits n) as Hdig.
  pose proof (decimal_round_trip n Hn) as Hrt.
  destruct (decimal_of_N n) as [| d ds] eqn:E.
  { exfalso. now apply (decimal_of_N_nonempty n). }
  inversion Hdig as [| ? ? Hd Hds]; subst.
  assert (Ht : take_digits (BS.append (BS.String d ds) rest) BS.EmptyString =
    (BS.String d ds, rest)).
  { rewrite take_digits_app by (assumption || exact Hrest). reflexivity. }
  assert (Hsk : skip_ws (BS.String d (BS.append ds rest)) =
    BS.String d (BS.append ds rest))
    by (apply skip_ws_head; now apply digit_not_ws).
  cbn [BS.append] in Ht |- *.
  cbn -[take_digits N_of_decimal strip_prefix lit digit_val skip_ws].
  rewrite Hsk. cbv beta iota.
  rewrite digit_not_quote by assumption.
  rewrite digit_not_lbrace by assumption.
  rewrite digit_not_true by assumption.
  rewrite digit_not_false by assumption.
  destruct (digit_val d) as [v |] eqn:Ed; [| now exfalso].
  rewrite Ht, Hrt. reflexivity.
Qed.

(* ---- booleans ----------------------------------------------------------- *)

(* The whole of [print (JBool b)] is a literal, so every test the parser makes
   is on a concrete byte and conversion settles it. *)
Lemma parse_value_bool : forall fuel (v : bool) rest,
  parse_value (S fuel) (BS.append (print (JBool v)) rest) = Some (JBool v, rest).
Proof. intros fuel v rest. destruct v; reflexivity. Qed.

(* ---- the field list, named --------------------------------------------- *)

(* [print]'s object case uses an inner [let fix go] rather than a top-level
   function, and it has to: a mutual [Fixpoint] would need [print]'s recursive
   argument to decrease on a [json] while [print_fields]' decreases on a
   [list (bytes * json)], which the guard checker will not accept across two
   unrelated inductives.  So the field printer is restated here and shown to
   agree with the one inside [print]. *)
Fixpoint print_fields (fs : list (bytes * json)) : bytes :=
  match fs with
  | [] => BS.EmptyString
  | [(k, v)] => BS.append (print_string k) (BS.String colon (print v))
  | (k, v) :: rest =>
      BS.append (print_string k)
        (BS.String colon (BS.append (print v) (BS.String comma (print_fields rest))))
  end.

Lemma print_JObj : forall fs, print (JObj fs) =
  BS.String lbrace (BS.append (print_fields fs) (BS.String rbrace BS.EmptyString)).
Proof.
  (* And they agree by conversion: the body above is alpha-equivalent to the
     [fix] inside [print], so unfolding both reaches the same term.  That is
     luck rather than design -- it holds only as long as the two stay written
     the same way, which is why the lemma exists at all instead of the proofs
     below leaning on the coincidence. *)
  reflexivity.
Qed.

Lemma print_string_app : forall k Y,
  BS.append (print_string k) Y = BS.String quote (BS.append k (BS.String quote Y)).
Proof. intros k Y. unfold print_string. cbn [BS.append]. now rewrite <- bytes_append_assoc. Qed.

(* Whatever follows, a non-empty field list starts with the opening quote of
   its first key.  Stated existentially because the byte after it depends on
   whether that field is the last one. *)
Lemma print_fields_cons_head : forall kv fs Y,
  exists tl, BS.append (print_fields (kv :: fs)) Y = BS.String quote tl.
Proof.
  intros [k v] fs Y. destruct fs as [| p fs'];
    cbn [print_fields]; rewrite <- bytes_append_assoc, print_string_app;
    eexists; reflexivity.
Qed.

(* The printed input, in the shape the parser consumes it: a leading quote,
   the key, the closing quote, the colon, the value, and then the tail.  Both
   are stated with the tail abstract so that [cbn] cannot wander into the rest
   of the field list while reducing the part in front of it. *)
Lemma print_fields_one_app : forall k v Y,
  BS.append (print_fields [(k, v)]) Y =
    BS.String quote (BS.append k (BS.String quote (BS.String colon (BS.append (print v) Y)))).
Proof.
  intros k v Y. cbn [print_fields].
  rewrite <- !bytes_append_assoc, print_string_app. reflexivity.
Qed.

(* Kept separate so that the tail stays folded: [cbn [print_fields]] on a
   two-or-more field list unfolds the tail as well, and then the two sides
   drift apart under reassociation. *)
Lemma print_fields_cons : forall k v kv fs,
  print_fields ((k, v) :: kv :: fs)
  = BS.append (print_string k)
      (BS.String colon (BS.append (print v) (BS.String comma (print_fields (kv :: fs))))).
Proof. reflexivity. Qed.

Lemma print_fields_cons_app : forall k v kv fs Y,
  BS.append (print_fields ((k, v) :: kv :: fs)) Y
  = BS.String quote (BS.append k (BS.String quote (BS.String colon
    (BS.append (print v) (BS.String comma (BS.append (print_fields (kv :: fs)) Y)))))).
Proof.
  intros k v kv fs Y.
  rewrite print_fields_cons, <- bytes_append_assoc. cbn [BS.append].
  rewrite <- bytes_append_assoc. cbn [BS.append].
  rewrite print_string_app. reflexivity.
Qed.

(* ---- what a round-trippable object looks like --------------------------- *)

(* Flat objects only.  [JObj] is excluded rather than handled: nesting would
   force the fuel bookkeeping and a remainder generalisation through
   [parse_value], and neither shape this service prints is nested. *)
Definition leaf_ok (v : json) : Prop :=
  match v with
  | JStr s => ok_string s
  | JNum n => n < 10 ^ 32
  | JBool _ => True
  | JObj _ => False
  end.

Definition field_ok (kv : bytes * json) : Prop :=
  ok_string (fst kv) /\ leaf_ok (snd kv).

(* Key distinctness, stated as the parser actually checks it: each key absent
   from the accumulator of fields already read.  Phrasing it this way rather
   than as [NoDup (map fst fs)] avoids needing to relate [has_key] and
   [bytes_eqb] to propositional equality -- and for a concrete object it is
   decided by conversion, since the keys are literals. *)
Fixpoint keys_fresh (fs : list (bytes * json)) (acc : list (bytes * json))
  : Prop :=
  match fs with
  | [] => True
  | kv :: rest => has_key (fst kv) acc = false /\ keys_fresh rest (kv :: acc)
  end.

Lemma parse_value_leaf : forall fuel v rest,
  leaf_ok v -> no_digit_next rest ->
  parse_value (S fuel) (BS.append (print v) rest) = Some (v, rest).
Proof.
  intros fuel v rest Hv Hr. destruct v as [s | n | b | fs].
  - cbn [print]. now apply parse_value_str.
  - cbn [print]. now apply parse_value_num.
  - now apply parse_value_bool.
  - now exfalso.
Qed.

(* ---- the field list, parsed back ---------------------------------------- *)

(* The induction that carries the accumulator.  [rev acc ++ fs] is the shape
   [parse_fields] builds: it reverses what it has collected and appends what
   is left, so the statement has to say that rather than just [fs]. *)
Lemma parse_fields_print : forall fs fuel acc rest,
  (List.length fs < fuel)%nat ->
  Forall field_ok fs ->
  keys_fresh fs acc ->
  parse_fields fuel (BS.append (print_fields fs) (BS.String rbrace rest)) acc
    = Some (rev acc ++ fs, rest).
Proof.
  induction fs as [| [k v] fs IH]; intros fuel acc rest Hf Hok Hk.
  - destruct fuel as [| fuel]; [ cbn in Hf; lia | ].
    cbn [print_fields BS.append]. cbn -[has_key].
    now rewrite app_nil_r.
  - cbn [Datatypes.length] in Hf.
    destruct fuel as [| fuel]; [ lia | ].
    destruct fuel as [| g]; [ lia | ].
    destruct Hk as [Hacc Hk].
    apply Forall_inv_tail in Hok as Hok'.
    apply Forall_inv in Hok. destruct Hok as [Hkok Hvok]. cbn [fst snd] in *.
    (* Freeze the inner fuel.  No [cbn] blocklist can stop the recursive call
       from unfolding -- inside the body it is a de Bruijn reference to the
       [fix], not the constant [parse_fields] -- but the [fix] only reduces
       when its fuel argument is a constructor, so keeping that argument a
       variable does what the blocklist cannot.  The [parse_value] step then
       gets its [S _] back in a side proof, where it does no harm. *)
    remember (S g) as f eqn:HF.
    destruct fs as [| p fs'].
    + (* the last field: a brace follows the value, not a comma *)
      rewrite print_fields_one_app.
       assert (Hpv : parse_value f (BS.append (print v) (BS.String rbrace rest))
                     = Some (v, BS.String rbrace rest))
        by (rewrite HF; apply parse_value_leaf; [ exact Hvok | reflexivity ]).
      (* [cbn] normalises [rbrace] and friends to their byte literals in the
         goal, so the hypotheses have to be normalised the same way or the
         rewrites find nothing. *)
      cbn -[parse_value print] in Hpv.
      cbn -[parse_string parse_value print].
      rewrite parse_string_print by exact Hkok. cbn [bytes_rev BS.rev BS.append].
      rewrite Hacc.
      cbn -[parse_value print].
      rewrite Hpv. cbn [rev]. reflexivity.
    + (* a comma, and then the next key has to open with a quote -- the
         parser's own no-trailing-comma check, which is why the tail is kept
         opaque here and only its head byte is supplied. *)
      rewrite print_fields_cons_app.
      remember (BS.append (print_fields (p :: fs')) (BS.String rbrace rest)) as R eqn:HR.
      destruct (print_fields_cons_head p fs' (BS.String rbrace rest)) as [tl Htl].
      assert (Hsk : skip_ws R = BS.String quote tl)
        by (rewrite HR, Htl; apply skip_ws_head; reflexivity).
       assert (Hpv : parse_value f (BS.append (print v) (BS.String comma R))
                     = Some (v, BS.String comma R))
        by (rewrite HF; apply parse_value_leaf; [ exact Hvok | reflexivity ]).
      cbn -[parse_value print] in Hpv. cbn -[skip_ws] in Hsk.
      cbn -[parse_string parse_value print].
      rewrite parse_string_print by exact Hkok. cbn [bytes_rev BS.rev BS.append].
      rewrite Hacc.
      cbn -[parse_value print].
      rewrite Hpv.
      (* [skip_ws] stays unblocked so it reduces past the concrete comma, and
         then sticks on [R] of its own accord. *)
      cbn -[parse_fields parse_value].
      rewrite Hsk. cbn -[parse_fields parse_value]. subst R.
      rewrite IH by (cbn [Datatypes.length] in *; (lia || assumption)).
      cbn [rev]. now rewrite <- app_assoc.
Qed.

(* ---- and the object ----------------------------------------------------- *)

Lemma parse_value_obj : forall fs fuel rest,
  (List.length fs < fuel)%nat ->
  Forall field_ok fs ->
  keys_fresh fs [] ->
  parse_value (S fuel) (BS.append (print (JObj fs)) rest) = Some (JObj fs, rest).
Proof.
  intros fs fuel rest Hf Hok Hk.
  rewrite print_JObj. cbn [BS.append]. rewrite <- bytes_append_assoc. cbn [BS.append].
  cbn -[parse_fields print_fields].
  rewrite parse_fields_print by assumption.
  reflexivity.
Qed.

(* The round trip, for the objects this service actually prints.  [parse]
   fixes the fuel at 16 and rejects trailing bytes, so the field count is
   bounded here rather than left as a parameter. *)
Theorem parse_print_obj : forall fs,
  (List.length fs < 15)%nat ->
  Forall field_ok fs ->
  keys_fresh fs [] ->
  Json.parse (print (JObj fs)) = Some (JObj fs).
Proof.
  intros fs Hf Hok Hk. unfold Json.parse.
  rewrite <- (bytes_append_empty (print (JObj fs))).
  rewrite (parse_value_obj fs 15 BS.EmptyString) by assumption.
  reflexivity.
Qed.
