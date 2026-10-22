;; Adapter: Argon2 as a CertiRocq registered primitive.
;;
;; Sits between two calling conventions.  Below it, the argon2 component's
;; canonical ABI: flat i32 parameters, lists as (pointer, length), results
;; returned indirectly into a caller-supplied area.  Above it, the CertiRocq
;; Wasm backend's value representation: `bytes` is a MetaRocq bytestring,
;; a chain of three-word heap cells, and allocation is a bump of `mem_ptr`.
;; Its EmptyString/String constructors have the same layout as nil/cons,
;; so the marshalling below is unchanged by the migration from `list byte`.
;;
;; Interface: components/crypto/wit/argon2.wit (repository-relative).
;; Build with `make component`; components/service/build.mjs merges the core adapters.
;; `make host-component` composes the resulting service with Rust providers.
;;
;; Registered env.ffi_* imports take i32 Rocq values, return void, and write
;; their Rocq return value into the imported mutable `rocq.result` global.
;; Pinned CertiRocq 6d34b50b emits an extra leading force dummy. Registrations
;; use actual arity + 1; registered wrappers accept and ignore that i32.
;;
;; Value representation, as probed from the backend's output:
;;
;;   EmptyString    immediate 1
;;   String h t     pointer to [tag=0 @0, h @4, t @8]
;;   byte v         immediate 2v+1
;;   false / true   immediate 1 / 3
;;   None           immediate 1
;;   Some x         pointer to [tag=0 @0, x @4]
;;   N0             immediate 1
;;   Npos p         pointer to [tag=0 @0, p @4]
;;   xH             immediate 1
;;   xI p / xO p    pointer to [tag @0, p @4], tag 0 / 1
;;
;; A record with k fields is a single-constructor block: [header @0, field_1
;; @4, ... field_k @(4k)], fields in declaration order.
;;
;; Note `true` is 3 and `false` is 1.  A boxed value's constructor index is
;; the low byte of its header word, which is why the tag reads below mask with
;; 255 rather than comparing the word.
(module
  ;; ---- from the CertiRocq module -------------------------------------------
  ;; `mem_ptr` is the bump allocator; there is no GC, so nothing is freed and
  ;; raw scratch bytes can share the heap with Rocq values safely.
  (import "rocq" "memory" (memory 1))
  (import "rocq" "mem_ptr" (global $mem_ptr (mut i32)))
  (import "rocq" "out_of_mem" (global $out_of_mem (mut i32)))
  (import "rocq" "result" (global $result (mut i32)))

  ;; ---- from the argon2 component -------------------------------------------
  ;; Canonical ABI lowerings of components/crypto/wit/argon2.wit. `params` is a record of
  ;; four u32, so it flattens to four i32 in field order; `algorithm` is an
  ;; enum, so one i32.  The results need more than one flat value, so they
  ;; come back through a return area we supply.
  (import "authentikate:crypto/argon2@0.1.0" "enroll"
    (func $wit_enroll
      (param i32 i32)          ;; password: ptr, len
      (param i32)))            ;; return area
  (import "authentikate:crypto/argon2@0.1.0" "verify"
    (func $wit_verify
      (param i32 i32)          ;; password: ptr, len
      (param i32 i32)          ;; salt: ptr, len
      (param i32)              ;; algorithm
      (param i32 i32 i32 i32)  ;; params
      (param i32 i32)          ;; expected: ptr, len
      (param i32)))            ;; return area

  ;; `$lower` returns a pointer and leaves the length here: a Wasm 1.0
  ;; function returns at most one value.
  (global $buf_len (mut i32) (i32.const 0))

  ;; Expanded at build/test time from common.wat; no runtime helper module.
  ;; @COMMON alloc cabi_realloc list_len read_N lower lift_bytes some@

  ;; ---- the registered primitives -------------------------------------------
  ;;
  ;; Export names must match the strings given to `CertiRocq Register`.
  ;;
  ;; Enrollment chooses parameters in the provider; verify uses the stored record.
  ;;
  ;; All return `option`, so a misuse of the interface (a short salt, an
  ;; over-long password, a tag of the wrong length) arrives in Rocq as `None`
  ;; rather than as a plausible answer.  The component's error message is
  ;; discarded: it is a string in linear memory and Rocq has nothing to do
  ;; with it.

  ;; argon2_verify : bytes -> bytes -> argon2_params -> bytes -> option bool
  ;;
  ;; The comparison stays inside the component, where it is `subtle::ct_eq`.
  ;; Returning the tag for Rocq to compare would be a timing oracle: equality
  ;; on bytestrings in extracted code short-circuits on the first differing byte.
  ;;
  ;; The parameters come from the caller, which is to say from the stored
  ;; record.  They have to: a tag only verifies under the parameters it was
  ;; derived with, so reading `recommended-params` here -- as this did -- would
  ;; invalidate every stored tag the day that recommendation moved.
  (func $argon2_verify
        (param $password i32) (param $salt i32) (param $params i32)
        (param $expected i32)
        (result i32)
    (local $pp i32) (local $pl i32)
    (local $sp i32) (local $sl i32)
    (local $ep i32) (local $el i32)
    (local $ret i32)

    (local.set $ret (call $alloc (i32.const 16) (i32.const 4)))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))

    (local.set $pp (call $lower (local.get $password)))
    (local.set $pl (global.get $buf_len))
    (local.set $sp (call $lower (local.get $salt)))
    (local.set $sl (global.get $buf_len))
    (local.set $ep (call $lower (local.get $expected)))
    (local.set $el (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))

    ;; `argon2_params` is a five-field record: algorithm at 4, then the four
    ;; fields of the WIT `params` in its declaration order -- memory-kib,
    ;; iterations, parallelism, tag-length.  The orders agree by construction;
    ;; Crypto.v says so and this is the other half of that agreement.
    (call $wit_verify
      (local.get $pp) (local.get $pl)
      (local.get $sp) (local.get $sl)
      (call $read_N (i32.load offset=4 (local.get $params)))
      (call $read_N (i32.load offset=8 (local.get $params)))
      (call $read_N (i32.load offset=12 (local.get $params)))
      (call $read_N (i32.load offset=16 (local.get $params)))
      (call $read_N (i32.load offset=20 (local.get $params)))
      (local.get $ep) (local.get $el)
      (local.get $ret))

    ;; result<bool, error>: discriminant at 0, payload at 4.  0 is ok, and the
    ;; ok payload is a single byte.  A Rocq bool is 1 for false, 3 for true.
    ;;
    ;; An out-of-range parameter arrives here as `invalid-params`, hence as
    ;; `None`, hence as a 500 -- not as `Some false`.  Which is the right way
    ;; round: a record this service cannot hash is not a wrong password.
    (if (result i32) (i32.load8_u (local.get $ret))
      (then (i32.const 1))  ;; err -> None
      (else
        (call $some
          (i32.or
            (i32.shl (i32.load8_u offset=4 (local.get $ret)) (i32.const 1))
            (i32.const 1))))))

  (func (export "ffi_argon2_verify")
        (param $force i32)
        (param $password i32) (param $salt i32) (param $params i32)
        (param $expected i32)
    (global.set $result
      (call $argon2_verify (local.get $password) (local.get $salt)
        (local.get $params) (local.get $expected))))

  ;; Secret.t is representation-identical to bytes, but opaque to Rocq callers.
  (func (export "ffi_secret_of_bytes") (param $force i32) (param $bytes i32)
    (global.set $result (local.get $bytes)))

  ;; argon2_enroll : Secret.t -> option bytes
  ;; The component generates the random salt and serializes the stored JSON
  ;; record. The adapter only moves bytes; no salt or tag is constructed here.
  (func $argon2_enroll (param $password i32) (result i32)
    (local $pp i32) (local $pl i32) (local $ret i32)
    (local.set $ret (call $alloc (i32.const 16) (i32.const 4)))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (local.set $pp (call $lower (local.get $password)))
    (local.set $pl (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (call $wit_enroll (local.get $pp) (local.get $pl) (local.get $ret))
    ;; result<list<u8>, error>: discriminant @0, ok pointer @4, length @8.
    (if (result i32) (i32.load8_u (local.get $ret))
      (then (i32.const 1))
      (else
        (call $some
          (call $lift_bytes
            (i32.load offset=4 (local.get $ret))
            (i32.load offset=8 (local.get $ret)))))))

  (func (export "ffi_argon2_enroll") (param $force i32) (param $password i32)
    (global.set $result (call $argon2_enroll (local.get $password))))

)
