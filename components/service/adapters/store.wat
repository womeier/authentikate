;; Adapter: wasi:keyvalue as a CertiRocq registered primitive.
;;
;; Same two calling conventions as components/service/adapters/argon2.wat, and the same
;; value representation -- see the header of that file, which documents it.
;; The allocator, the bytestring lowering and the bytestring lifting are copies of
;; the ones there.  They are copied rather than shared because wasm-merge
;; takes whole modules and these adapters are merged independently; a shared
;; prelude would need a fourth module and an import graph to go with it.
;;
;; Build with `make component`; components/service/build.mjs merges this alongside
;; the crypto adapters and the core extracted by components/service/theories/extraction.v.
;; Note that all three adapters export `cabi_realloc`, so the merge needs
;; --rename-export-conflicts and the component wrapping needs exactly one of
;; them to keep the name.
;;
;; THE ONE INTERFACE ASSUMPTION: wasi:keyvalue@0.2.0-draft, whose `store`
;; interface is
;;
;;   resource bucket { get: func(key: string) -> result<option<list<u8>>, error>; }
;;   bucket.set: func(key: string, value: list<u8>) -> result<_, error>;
;;   open: func(identifier: string) -> result<bucket, error>;
;;
;; The draft qualifier is load-bearing: this interface has changed shape
;; before (buckets were not resources in 0.1), and it will again.  What does
;; not change is the Rocq side -- `ffi_kv_get : bytes -> option (option bytes)`
;; is a statement about this file, not about WASI.
;;
;; Canonical ABI return-area layouts, both with a one-byte variant
;; discriminant padded to the payload's four-byte alignment:
;;
;; error is a variant { no-such-store, access-denied, other(string) }, not a
;; resource. Its discriminant is at 4 and its string payload at 8 and 12.
;;
;;   result<own<bucket>, error>          disc @0, handle-or-error @4    (16 b)
;;   result<option<list<u8>>, error>     disc @0, inner disc @4,
;;                                       ptr @8, len @12                (16 b)
;;   result<_, error>                   disc @0, error @4              (16 b)
(module
  ;; ---- from the CertiRocq module -------------------------------------------
  (import "rocq" "memory" (memory 1))
  (import "rocq" "mem_ptr" (global $mem_ptr (mut i32)))
  (import "rocq" "out_of_mem" (global $out_of_mem (mut i32)))
  (import "rocq" "result" (global $result (mut i32)))

  ;; ---- from the engine -----------------------------------------------------
  ;; No --plug for these: wasi:keyvalue is provided by the host, not by a
  ;; component of ours.
  (import "wasi:keyvalue/store@0.2.0-draft" "open"
    (func $wasi_open
      (param i32 i32)   ;; identifier: ptr, len
      (param i32)))     ;; return area
  (import "wasi:keyvalue/store@0.2.0-draft" "[method]bucket.get"
    (func $wasi_get
      (param i32)       ;; self: bucket handle
      (param i32 i32)   ;; key: ptr, len
      (param i32)))     ;; return area
  (import "wasi:keyvalue/store@0.2.0-draft" "[method]bucket.set"
    (func $wasi_set
      (param i32)       ;; self: bucket handle
      (param i32 i32)   ;; key: ptr, len
      (param i32 i32)   ;; value: ptr, len
      (param i32)))     ;; return area

  (global $buf_len (mut i32) (i32.const 0))

  ;; The bucket handle, opened on first use and kept for the life of the
  ;; instance.  -1 is "not open yet", which is not a valid handle.
  ;;
  ;; Caching it is only safe because there is no GC and no instance reuse: one
  ;; instance serves one request, so the handle cannot outlive a transaction
  ;; or go stale between callers.  If instances are ever pooled this has to
  ;; become a per-request open, or a reconnect on the first failure.
  (global $bucket (mut i32) (i32.const -1))

  ;; ---- allocation ----------------------------------------------------------

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

  ;; ---- Rocq values down to flat bytes, and back ----------------------------

  (func $list_len (param $l i32) (result i32)
    (local $n i32)
    (block $done
      (loop $next
        (br_if $done (i32.and (local.get $l) (i32.const 1)))
        (local.set $n (i32.add (local.get $n) (i32.const 1)))
        (local.set $l (i32.load offset=8 (local.get $l)))
        (br $next)))
    (local.get $n))

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

  (func $lift_bytes (param $p i32) (param $len i32) (result i32)
    (local $acc i32) (local $cell i32)
    (local.set $acc (i32.const 1))  ;; nil
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

  ;; ---- keys are strings, and a string is UTF-8 -----------------------------

  ;; wasi:keyvalue types its keys as `string`, so the canonical ABI will lift
  ;; the (pointer, length) pair below as UTF-8 and *trap* if it is not.  The
  ;; email in a login body is attacker-controlled, so without this check a
  ;; request carrying a stray 0xFF takes the instance down rather than failing
  ;; a login.
  ;;
  ;; Returns 1 if well-formed.  Rejects what RFC 3629 rejects and not merely
  ;; what the bit pattern permits: overlong encodings (0xC0, 0xC1, 0xE0 with a
  ;; low second byte, 0xF0 likewise), surrogates (0xED 0xA0..), and anything
  ;; above U+10FFFF (0xF5 and up).  A lenient check here would be a trap
  ;; later, which is the thing being avoided.
  ;;
  ;; Not constant-time, and it does not need to be: a key is an email address,
  ;; which is not a secret and is known to whoever sent it.
  (func $utf8_ok (param $p i32) (param $len i32) (result i32)
    (local $i i32) (local $b i32) (local $n i32)
    (local $lo i32) (local $hi i32) (local $j i32)
    (block $end
      (loop $next
        (br_if $end (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $b (i32.load8_u (i32.add (local.get $p) (local.get $i))))
        ;; ASCII, which is the whole of almost every key.
        (if (i32.lt_u (local.get $b) (i32.const 0x80))
          (then
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $next)))
        ;; A continuation byte here, or an overlong two-byte lead.
        (if (i32.lt_u (local.get $b) (i32.const 0xC2))
          (then (return (i32.const 0))))
        (local.set $lo (i32.const 0x80))
        (local.set $hi (i32.const 0xBF))
        (if (i32.lt_u (local.get $b) (i32.const 0xE0))
          (then (local.set $n (i32.const 1)))
          (else
            (if (i32.lt_u (local.get $b) (i32.const 0xF0))
              (then
                (local.set $n (i32.const 2))
                ;; 0xE0 80.. would be overlong; 0xED A0.. is a surrogate.
                (if (i32.eq (local.get $b) (i32.const 0xE0))
                  (then (local.set $lo (i32.const 0xA0))))
                (if (i32.eq (local.get $b) (i32.const 0xED))
                  (then (local.set $hi (i32.const 0x9F)))))
              (else
                (if (i32.ge_u (local.get $b) (i32.const 0xF5))
                  (then (return (i32.const 0))))
                (local.set $n (i32.const 3))
                ;; 0xF0 80.. overlong; 0xF4 90.. is past U+10FFFF.
                (if (i32.eq (local.get $b) (i32.const 0xF0))
                  (then (local.set $lo (i32.const 0x90))))
                (if (i32.eq (local.get $b) (i32.const 0xF4))
                  (then (local.set $hi (i32.const 0x8F))))))))
        ;; Truncated at the end of the key.
        (if (i32.ge_u (i32.add (local.get $i) (local.get $n)) (local.get $len))
          (then (return (i32.const 0))))
        ;; The first continuation byte carries the range that distinguishes an
        ;; overlong or a surrogate from a legitimate sequence.
        (local.set $b
          (i32.load8_u
            (i32.add (local.get $p) (i32.add (local.get $i) (i32.const 1)))))
        (if (i32.or (i32.lt_u (local.get $b) (local.get $lo))
                    (i32.gt_u (local.get $b) (local.get $hi)))
          (then (return (i32.const 0))))
        ;; The rest only have to be continuation bytes.
        (local.set $j (i32.const 2))
        (block $cdone
          (loop $cnext
            (br_if $cdone (i32.gt_u (local.get $j) (local.get $n)))
            (local.set $b
              (i32.load8_u
                (i32.add (local.get $p) (i32.add (local.get $i) (local.get $j)))))
            (if (i32.ne (i32.and (local.get $b) (i32.const 0xC0))
                        (i32.const 0x80))
              (then (return (i32.const 0))))
            (local.set $j (i32.add (local.get $j) (i32.const 1)))
            (br $cnext)))
        (local.set $i
          (i32.add (local.get $i) (i32.add (local.get $n) (i32.const 1))))
        (br $next)))
    (i32.const 1))

  ;; ---- the bucket ----------------------------------------------------------

  ;; The empty identifier is the default bucket.  A named one would need its
  ;; name as a (pointer, length) in this memory, and a `data` segment here
  ;; would write at a fixed offset into the CertiRocq heap -- so a named
  ;; bucket wants the host to place the string and hand over the pointer,
  ;; not a constant in this file.
  ;;
  ;; Returns -1 if the store cannot be opened, which becomes `None` and then
  ;; a 500.
  (func $bucket (result i32)
    (local $ret i32)
    (if (i32.ne (global.get $bucket) (i32.const -1))
      (then (return (global.get $bucket))))
    (local.set $ret (call $alloc (i32.const 16) (i32.const 4)))
    (if (global.get $out_of_mem) (then (return (i32.const -1))))
    (call $wasi_open (i32.const 0) (i32.const 0) (local.get $ret))
    (if (i32.load8_u (local.get $ret))
      (then
        (return (i32.const -1))))
    (global.set $bucket (i32.load offset=4 (local.get $ret)))
    (global.get $bucket))

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
    (local $kp i32) (local $kl i32) (local $b i32) (local $ret i32)

    (local.set $ret (call $alloc (i32.const 16) (i32.const 4)))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))

    (local.set $kp (call $lower (local.get $key)))
    (local.set $kl (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))

    ;; A key that is not UTF-8 names no account: every key this service writes
    ;; is an email that went through this same path.  So the honest answer is
    ;; absence, and it is also the only answer that keeps the instance alive.
    (if (i32.eqz (call $utf8_ok (local.get $kp) (local.get $kl)))
      (then (return (call $some (i32.const 1)))))

    (local.set $b (call $bucket))
    (if (i32.eq (local.get $b) (i32.const -1)) (then (return (i32.const 1))))

    (call $wasi_get
      (local.get $b) (local.get $kp) (local.get $kl) (local.get $ret))

    (if (result i32) (i32.load8_u (local.get $ret))
      (then
        ;; The error variant's message is discarded: it is a
        ;; string in linear memory and Rocq has nothing to do with it.  Which
        ;; is the one real cost of this design -- a store failure reaches the
        ;; logs as a bare 500, with the reason left on this side of the line.
        (i32.const 1))                                  ;; err -> None
      (else
        (if (result i32) (i32.load8_u offset=4 (local.get $ret))
          (then                                         ;; Some (Some v)
            (call $some
              (call $some
                (call $lift_bytes
                  (i32.load offset=8 (local.get $ret))
                  (i32.load offset=12 (local.get $ret))))))
          (else (call $some (i32.const 1)))))))          ;; Some None
  ;; Registered primitives return void and publish the Rocq value via result.
  ;; Pinned CertiRocq 6d34b50b emits an extra leading force dummy. Registrations
  ;; use actual arity + 1; registered wrappers accept and ignore that i32.
  (func (export "ffi_kv_get") (param $force i32) (param $key i32)
    (global.set $result (call $kv_get (local.get $key))))

  ;; kv_set : bytes -> bytes -> option bool
  ;; Publish Some true only after the host acknowledges the write. Invalid
  ;; UTF-8 keys and host failures are None, never successful acknowledgments.
  (func $kv_set (param $key i32) (param $value i32) (result i32)
    (local $kp i32) (local $kl i32) (local $vp i32) (local $vl i32)
    (local $b i32) (local $ret i32)
    (local.set $ret (call $alloc (i32.const 16) (i32.const 4)))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (local.set $kp (call $lower (local.get $key)))
    (local.set $kl (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (if (i32.eqz (call $utf8_ok (local.get $kp) (local.get $kl)))
      (then (return (i32.const 1))))
    (local.set $vp (call $lower (local.get $value)))
    (local.set $vl (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (local.set $b (call $bucket))
    (if (i32.eq (local.get $b) (i32.const -1)) (then (return (i32.const 1))))
    (call $wasi_set (local.get $b) (local.get $kp) (local.get $kl)
      (local.get $vp) (local.get $vl) (local.get $ret))
    (if (result i32) (i32.load8_u (local.get $ret))
      (then (i32.const 1))
      (else (call $some (i32.const 3)))))

  (func (export "ffi_kv_set")
        (param $force i32) (param $key i32) (param $value i32)
    (global.set $result (call $kv_set (local.get $key) (local.get $value))))
)
