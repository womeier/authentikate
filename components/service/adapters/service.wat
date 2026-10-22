;; Build template. Shared heap helpers are extracted from the Argon2 adapter.
;; Instances may serve sequential requests, but the bump heap is never reclaimed.
(module
  (type $apply-type (func (param i32 i32)))
  (import "rocq" "memory" (memory 1))
  (import "rocq" "table" (table 0 funcref))
  (import "rocq" "mem_ptr" (global $mem_ptr (mut i32)))
  (import "rocq" "out_of_mem" (global $out_of_mem (mut i32)))
  (import "rocq" "result" (global $result (mut i32)))
  (import "rocq" "main_function" (func $main))
  (import "argon2" "ffi_argon2_verify" (func $argon2-verify (param i32 i32 i32 i32 i32)))
  (import "argon2" "ffi_argon2_enroll" (func $argon2-enroll (param i32 i32)))
  (import "argon2" "ffi_secret_of_bytes" (func $secret (param i32 i32)))
  (import "hmac" "ffi_hmac_sign" (func $sign (param i32 i32 i32)))
  (import "hmac" "ffi_hmac_verify" (func $verify (param i32 i32 i32 i32)))
  (import "store" "ffi_kv_get" (func $get (param i32 i32)))
  (import "store" "ffi_kv_create" (func $create (param i32 i32 i32)))
  (import "email" "ffi_email_send" (func $email-send (param i32 i32 i32 i32 i32)))
  (import "wasi:clocks/wall-clock@0.2.0" "now" (func $now (param i32)))
  ;; Configuration, read here rather than taken as an argument.  `api` used to
  ;; carry an 8-field `config` record, which meant whoever called the service
  ;; -- the gateway, which terminates HTTP -- had to hold the signing seed and
  ;; call `import-key` to fill it in.  Reading it at this edge instead keeps
  ;; the seed inside the component that signs with it.  These are canonical
  ;; ABI lowerings: every result needs more than one flat value, so each call
  ;; takes a trailing return area.
  (import "authentikate:config/service@0.1.0" "get"
    (func $wit_settings (param i32)))        ;; return area: 32 bytes, align 8
  (import "authentikate:crypto/hmac@0.1.0" "import-key"
    (func $wit_import_key
      (param i32 i32)   ;; shared secret key: ptr, len
      (param i32)))     ;; return area: result<u32, error>, 16 bytes
  (import "authentikate:crypto/argon2@0.1.0" "recommended-params"
    (func $wit_recommended_params (param i32)))  ;; return area: 4 u32
  (global $initialized (mut i32) (i32.const 0))
  (global $api (mut i32) (i32.const 0))
  (global $buf_len (mut i32) (i32.const 0))
  ;; @HEAP_HELPERS@

  ;; Canonical byte buffers may leave the shared bump pointer unaligned, in
  ;; particular when an adapter returns immediate None instead of boxed Some.
  ;; Restore Rocq's tagged-pointer invariant before returning to generated code.
  (func $align-heap
    (global.set $mem_ptr
      (i32.and (i32.add (global.get $mem_ptr) (i32.const 3)) (i32.const -4))))
  (func (export "ffi_argon2_verify") (param $a i32) (param $b i32) (param $c i32) (param $d i32) (param $e i32)
    (call $argon2-verify (local.get $a) (local.get $b) (local.get $c) (local.get $d) (local.get $e))
    (call $align-heap))
  (func (export "ffi_argon2_enroll") (param $a i32) (param $b i32)
    (call $argon2-enroll (local.get $a) (local.get $b))
    (call $align-heap))
  (func (export "ffi_secret_of_bytes") (param $a i32) (param $b i32)
    (call $secret (local.get $a) (local.get $b))
    (call $align-heap))
  (func (export "ffi_hmac_sign") (param $a i32) (param $b i32) (param $c i32)
    (call $sign (local.get $a) (local.get $b) (local.get $c))
    (call $align-heap))
  (func (export "ffi_hmac_verify") (param $a i32) (param $b i32) (param $c i32) (param $d i32)
    (call $verify (local.get $a) (local.get $b) (local.get $c) (local.get $d))
    (call $align-heap))
  (func (export "ffi_kv_get") (param $a i32) (param $b i32)
    (call $get (local.get $a) (local.get $b))
    (call $align-heap))
  (func (export "ffi_kv_create") (param $a i32) (param $b i32) (param $c i32)
    (call $create (local.get $a) (local.get $b) (local.get $c))
    (call $align-heap))
  (func (export "ffi_email_send") (param $a i32) (param $b i32) (param $c i32) (param $d i32) (param $e i32)
    (call $email-send (local.get $a) (local.get $b) (local.get $c) (local.get $d) (local.get $e))
    (call $align-heap))

  (func $check
    (if (global.get $out_of_mem) (then unreachable)))
  (func $initialize
    (if (i32.eqz (global.get $initialized))
      (then
        (call $main)
        (call $check)
        (global.set $api (global.get $result))
        (global.set $initialized (i32.const 1)))))
  (func (export "cabi_realloc")
    (param $old i32) (param $size i32) (param $align i32) (param $new i32) (result i32)
    (local $p i32) (local $i i32)
    (call $initialize)
    (local.set $p (call $alloc (local.get $new) (local.get $align)))
    (call $check)
    (block $done (loop $copy
      (br_if $done (i32.ge_u (local.get $i) (local.get $size)))
      (br_if $done (i32.ge_u (local.get $i) (local.get $new)))
      (i32.store8 (i32.add (local.get $p) (local.get $i))
        (i32.load8_u (i32.add (local.get $old) (local.get $i))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $copy)))
    (local.get $p))
  (func $box (param $tag i32) (param $value i32) (result i32)
    (local $p i32)
    (local.set $p (call $alloc (i32.const 8) (i32.const 4)))
    (call $check)
    (i32.store (local.get $p) (local.get $tag))
    (i32.store offset=4 (local.get $p) (local.get $value))
    (local.get $p))
  (func $positive (param $n i64) (result i32)
    (if (result i32) (i64.eq (local.get $n) (i64.const 1))
      (then (i32.const 1))
      (else (call $box
        (i32.eqz (i32.wrap_i64 (i64.and (local.get $n) (i64.const 1))))
        (call $positive (i64.shr_u (local.get $n) (i64.const 1)))))))
  (func $N (param $n i64) (result i32)
    (if (result i32) (i64.eqz (local.get $n))
      (then (i32.const 1))
      (else (call $box (i32.const 0) (call $positive (local.get $n))))))
  (func $bytes-at (param $p i32) (result i32)
    (call $lift_bytes (i32.load (local.get $p)) (i32.load offset=4 (local.get $p))))
  (func $apply (param $closure i32) (param $arg i32) (result i32)
    (call $check)
    (call_indirect (type $apply-type)
      (i32.load offset=8 (local.get $closure)) (local.get $arg)
      (i32.load offset=4 (local.get $closure)))
    (call $check)
    (global.get $result))
  ;; A fixed salt for the missing-account hash, moved here from the gateway
  ;; when `config` stopped being an argument.  It is not a secret: it exists so
  ;; that a login for an unknown email runs the same Argon2 as one for a known
  ;; email with the wrong password.  Being constant costs nothing, because
  ;; `login_check` in Api.v returns Unauthorized whenever the lookup found
  ;; nothing, whatever the hash said.  16 bytes, over the 8-byte minimum
  ;; `derive` enforces.
  (func $dummy-salt (result i32)
    (local $p i32)
    (local.set $p (call $alloc (i32.const 16) (i32.const 8)))
    (call $check)
    (i64.store (local.get $p) (i64.const 0x69746e6568747561))          ;; "authenti"
    (i64.store offset=8 (local.get $p) (i64.const 0x7362612d6574616b)) ;; "kate-abs"
    (call $lift_bytes (local.get $p) (i32.const 16)))

  ;; `tag-length` zero bytes.  The value is discarded; only its length has to
  ;; match the parameters, or `verify` rejects the record on shape and the
  ;; absent path stops costing what the present path costs.
  (func $dummy-tag (param $len i32) (result i32)
    (local $p i32) (local $i i32)
    (local.set $p (call $alloc (local.get $len) (i32.const 4)))
    (call $check)
    (block $done (loop $zero
      (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
      (i32.store8 (i32.add (local.get $p) (local.get $i)) (i32.const 0))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $zero)))
    (call $lift_bytes (local.get $p) (local.get $len)))

  ;; `{"error":"Service is misconfigured"}` with a 500 -- byte for byte what
  ;; the gateway returned when it could not assemble `config`.  Now that the
  ;; seed is read here, the answer is owed here.  A trap would also become a
  ;; 500 in the host, but it would lose the body and kill the instance.
  (func $misconfigured (result i32)
    (local $p i32) (local $ret i32)
    (local.set $p (call $alloc (i32.const 36) (i32.const 4)))
    (call $check)
    (i64.store offset=0 (local.get $p) (i64.const 0x22726f727265227b))
    (i64.store offset=8 (local.get $p) (i64.const 0x636976726553223a))
    (i64.store offset=16 (local.get $p) (i64.const 0x73696d2073692065))
    (i64.store offset=24 (local.get $p) (i64.const 0x72756769666e6f63))
    (i32.store offset=32 (local.get $p) (i32.const 0x7d226465))
    (local.set $ret (call $alloc (i32.const 12) (i32.const 4)))
    (call $check)
    (i32.store (local.get $ret) (i32.const 500))
    (i32.store offset=4 (local.get $ret) (local.get $p))
    (i32.store offset=8 (local.get $ret) (i32.const 36))
    (local.get $ret))

  ;; `body` is two flat values, so it arrives directly rather than through an
  ;; indirect argument area; `config` is no longer a parameter at all.
  (func $dispatch (param $endpoint i32) (param $body-ptr i32) (param $body-len i32) (result i32)
    (local $cfg i32) (local $params i32)
    (local $pair i32) (local $body i32) (local $ret i32)
    (local $clock i32) (local $seconds i64)
    (local $set i32) (local $kr i32) (local $par i32)
    (local $key i32) (local $taglen i32)
    (call $initialize)
    ;; Canonical datetime is 16 bytes aligned to 8. Snapshot once per request.
    (local.set $clock (call $alloc (i32.const 16) (i32.const 8)))
    (call $check)
    (call $now (local.get $clock))
    (local.set $seconds (i64.load (local.get $clock)))

    ;; Configuration, once per request.  Handles are instance-local and an
    ;; instance is per-request, so the import has to repeat; what does not
    ;; change is the gateway's lack of access to the shared secret.
    ;; settings: key ptr/len @0, iss ptr/len @8, ttl @16, email-from @24.
    (local.set $set (call $alloc (i32.const 32) (i32.const 8)))
    (call $check)
    (call $wit_settings (local.get $set))

    (local.set $kr (call $alloc (i32.const 16) (i32.const 4)))
    (call $check)
    (call $wit_import_key
      (i32.load (local.get $set)) (i32.load offset=4 (local.get $set))
      (local.get $kr))
    ;; result<u32, error>: discriminant at 0, the handle at 4 on ok.
    (if (i32.load8_u (local.get $kr)) (then (return (call $misconfigured))))
    (local.set $key (i32.load offset=4 (local.get $kr)))

    (local.set $par (call $alloc (i32.const 16) (i32.const 4)))
    (call $check)
    (call $wit_recommended_params (local.get $par))
    (local.set $taglen (i32.load offset=12 (local.get $par)))
    ;; Canonical buffers may leave the bump pointer unaligned before Rocq
    ;; values are built on top of it.
    (call $align-heap)

    (local.set $cfg (call $alloc (i32.const 32) (i32.const 4)))
    (local.set $params (call $alloc (i32.const 24) (i32.const 4)))
    (call $check)
    (i32.store (local.get $cfg) (i32.const 0))
    (i32.store (local.get $params) (i32.const 0))
    ;; 2 is argon2id, the algorithm `enroll` writes into every record it mints;
    ;; the other four are `recommended-params` in field order.
    (i32.store offset=4 (local.get $params) (call $N (i64.const 2)))
    (i32.store offset=8 (local.get $params)
      (call $N (i64.extend_i32_u (i32.load (local.get $par)))))
    (i32.store offset=12 (local.get $params)
      (call $N (i64.extend_i32_u (i32.load offset=4 (local.get $par)))))
    (i32.store offset=16 (local.get $params)
      (call $N (i64.extend_i32_u (i32.load offset=8 (local.get $par)))))
    (i32.store offset=20 (local.get $params)
      (call $N (i64.extend_i32_u (local.get $taglen))))
    (i32.store offset=4 (local.get $cfg) (call $N (i64.extend_i32_u (local.get $key))))
    (i32.store offset=8 (local.get $cfg)
      (call $bytes-at (i32.add (local.get $set) (i32.const 8))))
    (i32.store offset=12 (local.get $cfg) (call $N (i64.load offset=16 (local.get $set))))
    (i32.store offset=16 (local.get $cfg) (call $dummy-salt))
    (i32.store offset=20 (local.get $cfg) (call $dummy-tag (local.get $taglen)))
    (i32.store offset=24 (local.get $cfg) (local.get $params))
    (i32.store offset=28 (local.get $cfg)
      (call $bytes-at (i32.add (local.get $set) (i32.const 24))))
    (local.set $pair (call $apply
      (call $apply
        (call $apply (i32.load (i32.add (global.get $api) (local.get $endpoint))) (local.get $cfg))
        (call $N (local.get $seconds)))
      (call $lift_bytes (local.get $body-ptr) (local.get $body-len))))
    (local.set $body (call $lower (i32.load offset=8 (local.get $pair))))
    (local.set $ret (call $alloc (i32.const 12) (i32.const 4)))
    (call $check)
    (i32.store (local.get $ret) (call $read_N (i32.load offset=4 (local.get $pair))))
    (i32.store offset=4 (local.get $ret) (local.get $body))
    (i32.store offset=8 (local.get $ret) (global.get $buf_len))
    (local.get $ret))
  (func (export "authentikate:service/api@0.1.0#login") (param $p i32) (param $n i32) (result i32)
    (call $dispatch (i32.const 4) (local.get $p) (local.get $n)))
  (func (export "authentikate:service/api@0.1.0#validate") (param $p i32) (param $n i32) (result i32)
    (call $dispatch (i32.const 8) (local.get $p) (local.get $n)))
  (func (export "authentikate:service/api@0.1.0#signup") (param $p i32) (param $n i32) (result i32)
    (call $dispatch (i32.const 12) (local.get $p) (local.get $n)))
)
