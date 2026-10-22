;; Adapter: HMAC-SHA-256 as a CertiRocq registered primitive.
;;
;; Companion to argon2.wat. Both export `cabi_realloc` and carry the same
;; marshalling helpers; the service assembly retains only its public allocator.
;;
;; Interface: components/crypto/wit/hmac.wit (repository-relative).
;; Build with `make component`; components/service/build.mjs merges the core adapters.
;; `make host-component` composes the resulting service with Rust providers.
;;
;; Registered env.ffi_* imports take i32 Rocq values, return void, and write
;; their Rocq return value into the imported mutable `rocq.result` global.
;; Pinned CertiRocq 6d34b50b emits an extra leading force dummy. Registrations
;; use actual arity + 1; registered wrappers accept and ignore that i32.
;;
;; Value representation (probed from the backend's output):
;;
;;   EmptyString    immediate 1
;;   String h t     pointer to [tag=0 @0, h @4, t @8]
;;   byte v         immediate 2v+1
;;   false / true   immediate 1 / 3
;;   None           immediate 1
;;   Some x         pointer to [tag=0 @0, x @4]
(module
  ;; ---- from the CertiRocq module -------------------------------------------
  (import "rocq" "memory" (memory 1))
  (import "rocq" "mem_ptr" (global $mem_ptr (mut i32)))
  (import "rocq" "out_of_mem" (global $out_of_mem (mut i32)))
  (import "rocq" "result" (global $result (mut i32)))

  ;; ---- from the hmac component ------------------------------------------
  ;; Canonical ABI lowerings of components/crypto/wit/hmac.wit. Every result needs more
  ;; than one flat value, so each call takes a trailing return area.
  (import "authentikate:crypto/hmac@0.1.0" "sign"
    (func $wit_sign
      (param i32)       ;; configured key handle: u32
      (param i32 i32)   ;; message: ptr, len
      (param i32)))     ;; return area
  (import "authentikate:crypto/hmac@0.1.0" "verify"
    (func $wit_verify
      (param i32)       ;; configured shared-key handle: u32
      (param i32 i32)   ;; message: ptr, len
      (param i32 i32)   ;; signature: ptr, len
      (param i32)))     ;; return area

  ;; `$lower` returns a pointer and leaves the length here: a Wasm 1.0
  ;; function returns at most one value.
  (global $buf_len (mut i32) (i32.const 0))

  ;; Expanded at build/test time from common.wat; checked keys stay local.
  ;; @COMMON alloc cabi_realloc list_len lower lift_bytes some@

  ;; Key.t is an opaque N. Reject values wider than u32 before calling WIT.
  ;; Return i64 so every u32, including 0xffffffff, is distinct from failure.
  (func $read_key (param $n i32) (result i64)
    (local $acc i64) (local $w i64)
    (if (i32.and (local.get $n) (i32.const 1))
      (then (return (i64.const 0))))
    (local.set $n (i32.load offset=4 (local.get $n)))
    (local.set $w (i64.const 1))
    (block $done
      (loop $next
        (if (i64.gt_u (local.get $w) (i64.const 0x80000000))
          (then (return (i64.const -1))))
        (br_if $done (i32.and (local.get $n) (i32.const 1)))
        (if (i32.eqz (i32.and (i32.load (local.get $n)) (i32.const 255)))
          (then (local.set $acc (i64.add (local.get $acc) (local.get $w)))))
        (local.set $w (i64.shl (local.get $w) (i64.const 1)))
        (local.set $n (i32.load offset=4 (local.get $n)))
        (br $next)))
    (i64.add (local.get $acc) (local.get $w)))

  ;; ---- the registered primitives -------------------------------------------
  ;;
  ;; Export names must match the strings given to `CertiRocq Register`.
  ;;
  ;; Both return `option`: an unknown handle or a tag of the wrong length
  ;; arrives in Rocq as `None`
  ;; rather than as a plausible answer.  The component's error string stays in
  ;; linear memory and is discarded.
  ;;
  ;; Both signing and verification depend on the shared secret. Only an opaque
  ;; handle crosses this boundary; MAC computation and tag comparison stay inside
  ;; the component. Source-level constant-time discipline is not a Wasm timing proof.

  ;; hmac_sign : Key.t -> bytes -> option bytes
  (func $hmac_sign
        (param $key i32) (param $message i32) (result i32)
    (local $handle i64)
    (local $mp i32) (local $ml i32)
    (local $ret i32)

    (local.set $handle (call $read_key (local.get $key)))
    (if (i64.eq (local.get $handle) (i64.const -1))
      (then (return (i32.const 1))))
    (local.set $ret (call $alloc (i32.const 16) (i32.const 4)))
    (local.set $mp (call $lower (local.get $message)))
    (local.set $ml (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))

    (call $wit_sign
      (i32.wrap_i64 (local.get $handle))
      (local.get $mp) (local.get $ml)
      (local.get $ret))

    ;; result<list<u8>, error>: discriminant at 0; on ok, pointer at 4 and
    ;; length at 8, allocated in our memory through `cabi_realloc`.
    (if (result i32) (i32.load8_u (local.get $ret))
      (then (i32.const 1))  ;; err -> None
      (else
        (call $some
          (call $lift_bytes
            (i32.load offset=4 (local.get $ret))
            (i32.load offset=8 (local.get $ret)))))))

  ;; hmac_verify : Key.t -> bytes -> bytes -> option bool
  ;;
  ;; `Some false` is an answer -- the signature does not match -- and is not
  ;; the same as `None`, which means an input was the wrong shape and no
  ;; question was asked. Tag length and constant-time equality are checked inside
  ;; the component.
  (func $hmac_verify
         (param $key i32) (param $message i32) (param $signature i32)
        (result i32)
    (local $handle i64)
    (local $mp i32) (local $ml i32)
    (local $sp i32) (local $sl i32)
    (local $ret i32)

    (local.set $handle (call $read_key (local.get $key)))
    (if (i64.eq (local.get $handle) (i64.const -1))
      (then (return (i32.const 1))))
    (local.set $ret (call $alloc (i32.const 16) (i32.const 4)))
    (local.set $mp (call $lower (local.get $message)))
    (local.set $ml (global.get $buf_len))
    (local.set $sp (call $lower (local.get $signature)))
    (local.set $sl (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))

    (call $wit_verify
      (i32.wrap_i64 (local.get $handle))
      (local.get $mp) (local.get $ml)
      (local.get $sp) (local.get $sl)
      (local.get $ret))

    ;; result<bool, error>: discriminant at 0, the ok payload one byte at 4.
    ;; A Rocq bool is 1 for false, 3 for true.
    (if (result i32) (i32.load8_u (local.get $ret))
      (then (i32.const 1))  ;; err -> None
      (else
        (call $some
          (i32.or
            (i32.shl (i32.load8_u offset=4 (local.get $ret)) (i32.const 1))
            (i32.const 1))))))

  (func (export "ffi_hmac_sign")
        (param $force i32) (param $key i32) (param $message i32)
    (global.set $result
      (call $hmac_sign (local.get $key) (local.get $message))))

  (func (export "ffi_hmac_verify")
        (param $force i32)
        (param $key i32) (param $message i32) (param $signature i32)
    (global.set $result
      (call $hmac_verify (local.get $key) (local.get $message)
        (local.get $signature))))

)
