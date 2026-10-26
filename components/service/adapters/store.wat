;; Adapter: accounts.get/create as CertiRocq registered primitives.
;;
;; Same two calling conventions as components/service/adapters/argon2.wat, and the same
;; value representation -- see the header of that file, which documents it.
;; Heap and UTF-8 helpers are expanded from common.wat by expand.mjs at build
;; and test time, without introducing a runtime module or import graph.
;;
;; Build with `make component`; components/service/build.mjs merges this alongside
;; the crypto adapters and the core extracted by components/service/theories/extraction.v.
;; Note that all three adapters export `cabi_realloc`, so the merge needs
;; --rename-export-conflicts and the component wrapping needs exactly one of
;; them to keep the name.
;;
;; Interface: authentikate:storage/accounts@0.1.0.
;;
;;   get: func(key: string) -> result<list<u8>, error>;
;;   create: func(key: string, value: list<u8>) -> result<_, error>;
;;
;; No buckets, resource handles, or overwrite primitive. The provider must make
;; create atomic and its successful writes readable, as assumed in Proofs.v.
;;
;; Canonical ABI return-area layouts, each with a one-byte variant
;; discriminant padded to the payload's alignment:
;;
;; error is a payload-free variant { not-found, already-exists, unavailable },
;; with discriminants 0, 1, 2 respectively (in WIT declaration order).
;;
;;   result<list<u8>, error>            disc @0, ptr-or-error @4,
;;                                       len @8                        (12 b)
;;   result<_, error>                   disc @0, error @1               (2 b)
(module
  ;; ---- from the CertiRocq module -------------------------------------------
  (import "rocq" "memory" (memory 1))
  (import "rocq" "mem_ptr" (global $mem_ptr (mut i32)))
  (import "rocq" "out_of_mem" (global $out_of_mem (mut i32)))
  (import "rocq" "result" (global $result (mut i32)))

  ;; ---- from the accounts provider -----------------------------------------
  (import "authentikate:storage/accounts@0.1.0" "get"
    (func $accounts_get
      (param i32 i32)   ;; key: ptr, len
      (param i32)))     ;; return area
  (import "authentikate:storage/accounts@0.1.0" "create"
    (func $accounts_create
      (param i32 i32)   ;; key: ptr, len
      (param i32 i32)   ;; value: ptr, len
      (param i32)))     ;; return area

  (global $buf_len (mut i32) (i32.const 0))

  ;; @COMMON alloc cabi_realloc list_len lower lift_bytes some utf8_ok@

  ;; ---- the registered primitives -------------------------------------------

  ;; kv_get : bytes -> option (option bytes)
  ;;
  ;; The nesting is the point.  `None` is the store refusing and becomes a
  ;; 500; `Some None` is the key being absent and becomes the dummy-hash path
  ;; and a 401.  An adapter that collapsed the two would turn a store outage
  ;; into "no such user" on every account at once -- which is why the Rocq
  ;; type has room for both, and why this function has three exits.
  ;;
  ;; What it does not do is interpret the value.  Decoding belongs to
  ;; Store.decode, inside the verified perimeter; this moves bytes.
  (func $kv_get (param $key i32) (result i32)
    (local $kp i32) (local $kl i32) (local $ret i32)

    (local.set $ret (call $alloc (i32.const 12) (i32.const 4)))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))

    (local.set $kp (call $lower (local.get $key)))
    (local.set $kl (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))

    ;; A key that is not UTF-8 names no account: every key this service writes
    ;; is an email that went through this same path.  So the honest answer is
    ;; absence, and it is also the only answer that keeps the instance alive.
    (if (i32.eqz (call $utf8_ok (local.get $kp) (local.get $kl)))
      (then (return (call $some (i32.const 1)))))

    (call $accounts_get
      (local.get $kp) (local.get $kl) (local.get $ret))

    (if (result i32) (i32.load8_u (local.get $ret))
      (then
        ;; Only not-found is absence; even already-exists is a refusal here.
        (if (result i32) (i32.eqz (i32.load8_u offset=4 (local.get $ret)))
          (then (call $some (i32.const 1)))
          (else (i32.const 1))))
      (else
        (call $some
          (call $some
            (call $lift_bytes
              (i32.load offset=4 (local.get $ret))
              (i32.load offset=8 (local.get $ret))))))))
  ;; Registered primitives return void and publish the Rocq value via result.
  ;; Pinned CertiRocq 6d34b50b emits an extra leading force dummy. Registrations
  ;; use actual arity + 1; registered wrappers accept and ignore that i32.
  (func (export "ffi_kv_get") (param $force i32) (param $key i32)
    (global.set $result (call $kv_get (local.get $key))))

  ;; kv_create : bytes -> bytes -> option bool
  ;;
  ;; Create-if-absent, and the three answers are three different facts.
  ;; `Some true` is this caller creating the pair. `Some false` is the key
  ;; being taken, including a lost race. `None` is the store refusing; an invalid
  ;; UTF-8 key is one such refusal: it names no account and cannot be written.
  ;;
  ;; Atomicity is the provider's responsibility, not implemented as get-then-set.
  (func $kv_create (param $key i32) (param $value i32) (result i32)
    (local $kp i32) (local $kl i32) (local $vp i32) (local $vl i32)
    (local $ret i32)
    (local.set $ret (call $alloc (i32.const 2) (i32.const 1)))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (local.set $kp (call $lower (local.get $key)))
    (local.set $kl (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (if (i32.eqz (call $utf8_ok (local.get $kp) (local.get $kl)))
      (then (return (i32.const 1))))
    (local.set $vp (call $lower (local.get $value)))
    (local.set $vl (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (call $accounts_create
      (local.get $kp) (local.get $kl) (local.get $vp) (local.get $vl) (local.get $ret))
    (if (result i32) (i32.load8_u (local.get $ret))
      (then
        ;; Only already-exists is a conflict; not-found is inappropriate here.
        (if (result i32) (i32.eq (i32.load8_u offset=1 (local.get $ret)) (i32.const 1))
          (then (call $some (i32.const 1)))
          (else (i32.const 1))))
      (else (call $some (i32.const 3)))))

  (func (export "ffi_kv_create")
        (param $force i32) (param $key i32) (param $value i32)
    (global.set $result (call $kv_create (local.get $key) (local.get $value))))
)
