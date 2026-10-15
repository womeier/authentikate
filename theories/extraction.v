(******************************************************************************)
(*  Wasm extraction via CertiRocq                                             *)
(*                                                                            *)
(*  For now this is the toolchain smoke test: one entry point, compiled, so   *)
(*  that a green build means rocq, the CertiRocq plugin and its Wasm backend  *)
(*  all work.  It grows into the real API record (see PLAN.md): one record    *)
(*  of entry points, one module, one linear memory.                           *)
(******************************************************************************)

From Stdlib Require Import List Strings.Byte.
From Authentikate Require Import Bytes.
From CertiRocq.Plugin Require Import CertiRocq.

Import ListNotations.

(* Round-trips its input: enough to exercise blocks, immediates and a
   closure call across the host boundary. *)
Definition echo (bs : bytes) : bytes := bs.

Record api : Set := MkApi {
  api_echo : bytes -> bytes
}.

Definition authentikate_api : api := {| api_echo := echo |}.

Eval vm_compute in (api_echo authentikate_api [x68; x69]).

CertiRocq Compile Wasm authentikate_api.
