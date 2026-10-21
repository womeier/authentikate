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
;; Interface: providers/crypto/wit/argon2.wit (repository-relative).
;; Build with `make component`; component/build.mjs merges the core adapters.
;; `make host-component` composes the resulting service with Rust providers.
;;
;; Registered env.ffi_* imports take i32 Rocq values, return void, and write
;; their Rocq return value into the imported mutable `rocq.result` global.
;; Pinned CertiRocq 6d34b50b emits an extra leading force dummy. Registrations
;; use actual arity + 1; registered wrappers accept and ignore that i32.
;; The unregistered derive auxiliary retains its direct i32 return.
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
  ;; Canonical ABI lowerings of providers/crypto/wit/argon2.wit. `params` is a record of
  ;; four u32, so it flattens to four i32 in field order; `algorithm` is an
  ;; enum, so one i32.  The results need more than one flat value, so they
  ;; come back through a return area we supply.
  (import "authentikate:crypto/argon2@0.1.0" "recommended-params"
    (func $wit_recommended_params (param i32)))
  (import "authentikate:crypto/argon2@0.1.0" "enroll"
    (func $wit_enroll
      (param i32 i32)          ;; password: ptr, len
      (param i32)))            ;; return area
  (import "authentikate:crypto/argon2@0.1.0" "derive"
    (func $wit_derive
      (param i32 i32)          ;; password: ptr, len
      (param i32 i32)          ;; salt: ptr, len
      (param i32)              ;; algorithm
      (param i32 i32 i32 i32)  ;; params
      (param i32)))            ;; return area
  (import "authentikate:crypto/argon2@0.1.0" "verify"
    (func $wit_verify
      (param i32 i32)          ;; password: ptr, len
      (param i32 i32)          ;; salt: ptr, len
      (param i32)              ;; algorithm
      (param i32 i32 i32 i32)  ;; params
      (param i32 i32)          ;; expected: ptr, len
      (param i32)))            ;; return area

  ;; `ffi_argon2_derive` still mints tags under `recommended-params` and under
  ;; argon2id, the third case of the `algorithm` enum.  `verify` no longer
  ;; does: a tag is only verifiable under the parameters it was derived with,
  ;; so those come up from the stored record instead.
  ;;
  ;; If the constant-time requirement is taken as unconditional, this becomes
  ;; 1 (argon2i): argon2id's addressing is data-dependent after the first half
  ;; pass, so its memory access pattern depends on the password.  That channel
  ;; needs a local observer, which is why RFC 9106 still recommends argon2id;
  ;; the cost of argon2i is weaker time-memory-tradeoff resistance, to be paid
  ;; back with more iterations than `recommended-params` returns.
  (global $algorithm i32 (i32.const 2))

  ;; `$lower` returns a pointer and leaves the length here: a Wasm 1.0
  ;; function returns at most one value.
  (global $buf_len (mut i32) (i32.const 0))

  ;; ---- allocation ----------------------------------------------------------

  ;; Bump-allocate $n bytes aligned to $align (a power of two), growing the
  ;; memory as needed.  Sets `out_of_mem` and returns 0 if it cannot.
  ;;
  ;; The backend pre-grows only 52 bytes around an `Eprim` node, which is
  ;; nowhere near enough for a `bytes` result at 12 bytes per cons cell, so
  ;; this does its own growing rather than trusting that headroom.
  (func $alloc (param $n i32) (param $align i32) (result i32)
    (local $p i32) (local $end i32) (local $have i32) (local $pages i32)
    (local.set $p
      (i32.and
        (i32.add (global.get $mem_ptr) (i32.sub (local.get $align) (i32.const 1)))
        (i32.xor (i32.sub (local.get $align) (i32.const 1)) (i32.const -1))))
    (local.set $end (i32.add (local.get $p) (local.get $n)))
    (local.set $have (i32.shl (memory.size) (i32.const 16)))
    (if (i32.gt_u (local.get $end) (local.get $have))
      (then
        (local.set $pages
          (i32.add
            (i32.shr_u
              (i32.sub (local.get $end) (local.get $have))
              (i32.const 16))
            (i32.const 1)))
        (if (i32.eq (memory.grow (local.get $pages)) (i32.const -1))
          (then
            (global.set $out_of_mem (i32.const 1))
            (return (i32.const 0))))))
    (global.set $mem_ptr (local.get $end))
    (local.get $p))

  ;; The canonical ABI allocates a returned list in *our* memory, through
  ;; this.  Nothing is ever freed, so a resize is a fresh allocation and a
  ;; copy; a byte loop rather than memory.copy keeps the adapter inside
  ;; Wasm 1.0, which is what the CertiRocq module is.
  (func (export "cabi_realloc")
        (param $old_ptr i32) (param $old_size i32)
        (param $align i32) (param $new_size i32) (result i32)
    (local $p i32) (local $i i32) (local $n i32)
    (local.set $p (call $alloc (local.get $new_size) (local.get $align)))
    (if (global.get $out_of_mem) (then (return (i32.const 0))))
    (local.set $n (local.get $old_size))
    (if (i32.gt_u (local.get $n) (local.get $new_size))
      (then (local.set $n (local.get $new_size))))
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
        (i32.store8
          (i32.add (local.get $p) (local.get $i))
          (i32.load8_u (i32.add (local.get $old_ptr) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))
    (local.get $p))

  ;; ---- Rocq values down to flat bytes --------------------------------------

  ;; A bytestring ends at the immediate EmptyString, which is odd; every String cell
  ;; is a four-aligned pointer, so the low bit is the discriminator.
  (func $list_len (param $l i32) (result i32)
    (local $n i32)
    (block $done
      (loop $next
        (br_if $done (i32.and (local.get $l) (i32.const 1)))
        (local.set $n (i32.add (local.get $n) (i32.const 1)))
        (local.set $l (i32.load offset=8 (local.get $l)))
        (br $next)))
    (local.get $n))

  ;; An `N` down to an i32.  `positive` is a big-endian-ish bit list read from
  ;; the least significant end -- `xH` is 1, `xI p` is 2p+1, `xO p` is 2p --
  ;; so the natural traversal is outside-in and the weight doubles as it goes.
  ;;
  ;; Truncates silently past 2^32.  That is sound here only because
  ;; `Store.of_json` rejects any parameter that does not fit a u32 before it
  ;; can reach this function, which is the whole reason that check exists: the
  ;; alternative is hashing under a cost nobody wrote down.  A caller that
  ;; skips the check gets wraparound, not an error.
  ;;
  ;; This also explains why the cost knobs are `N` and not `nat` in Crypto.v:
  ;; 19456 as a unary `nat` is 19456 heap cells to walk, per login.
  (func $read_N (param $n i32) (result i32)
    (local $acc i32) (local $w i32)
    ;; N0
    (if (i32.and (local.get $n) (i32.const 1)) (then (return (i32.const 0))))
    ;; Npos p
    (local.set $n (i32.load offset=4 (local.get $n)))
    (local.set $w (i32.const 1))
    (block $done
      (loop $next
        ;; xH: the leading one bit, and the end of the list.
        (br_if $done (i32.and (local.get $n) (i32.const 1)))
        (if (i32.eqz (i32.and (i32.load (local.get $n)) (i32.const 255)))
          (then (local.set $acc (i32.add (local.get $acc) (local.get $w)))))
        (local.set $w (i32.shl (local.get $w) (i32.const 1)))
        (local.set $n (i32.load offset=4 (local.get $n)))
        (br $next)))
    (i32.add (local.get $acc) (local.get $w)))

  ;; Flatten a `bytes` into a fresh buffer; length lands in $buf_len.
  (func $lower (param $l i32) (result i32)
    (local $len i32) (local $p i32) (local $i i32)
    (local.set $len (call $list_len (local.get $l)))
    (global.set $buf_len (local.get $len))
    (local.set $p (call $alloc (local.get $len) (i32.const 1)))
    (if (global.get $out_of_mem) (then (return (i32.const 0))))
    (block $done
      (loop $next
        (br_if $done (i32.and (local.get $l) (i32.const 1)))
        (i32.store8
          (i32.add (local.get $p) (local.get $i))
          (i32.shr_u (i32.load offset=4 (local.get $l)) (i32.const 1)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (local.set $l (i32.load offset=8 (local.get $l)))
        (br $next)))
    (local.get $p))

  ;; ---- flat bytes back up to Rocq values -----------------------------------

  ;; Built back to front, so each cell's tail is already in hand.
  (func $lift_bytes (param $p i32) (param $len i32) (result i32)
    (local $acc i32) (local $cell i32)
    (local.set $acc (i32.const 1))  ;; EmptyString
    (block $done
      (loop $next
        (br_if $done (i32.eqz (local.get $len)))
        (local.set $len (i32.sub (local.get $len) (i32.const 1)))
        (local.set $cell (call $alloc (i32.const 12) (i32.const 4)))
        (if (global.get $out_of_mem) (then (return (i32.const 1))))
        (i32.store (local.get $cell) (i32.const 0))
        (i32.store offset=4 (local.get $cell)
          (i32.or
            (i32.shl
              (i32.load8_u (i32.add (local.get $p) (local.get $len)))
              (i32.const 1))
            (i32.const 1)))
        (i32.store offset=8 (local.get $cell) (local.get $acc))
        (local.set $acc (local.get $cell))
        (br $next)))
    (local.get $acc))

  (func $some (param $x i32) (result i32)
    (local $cell i32)
    (local.set $cell (call $alloc (i32.const 8) (i32.const 4)))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (i32.store (local.get $cell) (i32.const 0))
    (i32.store offset=4 (local.get $cell) (local.get $x))
    (local.get $cell))

  ;; ---- the registered primitives -------------------------------------------
  ;;
  ;; Export names must match the strings given to `CertiRocq Register`.
  ;;
  ;; Derive uses recommended parameters; verify uses the stored Rocq record.
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

  ;; argon2_derive : bytes -> bytes -> option bytes
  ;;
  ;; Here only to mint a stored tag when a user is created.  Nothing on the
  ;; login path should call it: deriving in order to compare in Rocq is the
  ;; mistake `verify` exists to prevent.
  (func (export "ffi_argon2_derive")
        (param $password i32) (param $salt i32) (result i32)
    (local $pp i32) (local $pl i32)
    (local $sp i32) (local $sl i32)
    (local $par i32) (local $ret i32)

    (local.set $ret (call $alloc (i32.const 16) (i32.const 4)))
    (local.set $par (call $alloc (i32.const 16) (i32.const 4)))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (call $wit_recommended_params (local.get $par))

    (local.set $pp (call $lower (local.get $password)))
    (local.set $pl (global.get $buf_len))
    (local.set $sp (call $lower (local.get $salt)))
    (local.set $sl (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))

    (call $wit_derive
      (local.get $pp) (local.get $pl)
      (local.get $sp) (local.get $sl)
      (global.get $algorithm)
      (i32.load (local.get $par))
      (i32.load offset=4 (local.get $par))
      (i32.load offset=8 (local.get $par))
      (i32.load offset=12 (local.get $par))
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
)
