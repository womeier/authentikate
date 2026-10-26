;; Build-time fragment, not a runtime module. Templates select named functions.
;; Requires $mem_ptr, $out_of_mem and memory; $lower also writes $buf_len.

;; Bump allocation preserves the adapters' alignment, growth and OOM behavior.
;; CertiRocq's Eprim headroom cannot hold byte strings at 12 bytes per cell.
;; TODO: simplify by exporting grow_mem_if_necessary publicly in CertiRocq's Wasm backend
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

;; No freeing: resizing allocates afresh and copies min(old_size, new_size).
;; The public service allocator separately initializes and traps on OOM.
(func $cabi_realloc (export "cabi_realloc")
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

;; EmptyString is immediate 1; String cells are [tag, byte, tail].
(func $list_len (param $l i32) (result i32)
  (local $n i32)
  (block $done
    (loop $next
      (br_if $done (i32.and (local.get $l) (i32.const 1)))
      (local.set $n (i32.add (local.get $n) (i32.const 1)))
      (local.set $l (i32.load offset=8 (local.get $l)))
      (br $next)))
  (local.get $n))

;; Flatten bytes into fresh memory, leaving the length in $buf_len.
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

;; Build back to front so each cell's tail is already in hand.
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

;; N0 = 1, Npos = [tag, positive], xH = 1, xI/xO = [0/1, positive].
;; This decoder truncates past u32. Stored Argon2 costs are range-checked by
;; Store.of_json; HMAC's checked key decoder must remain separate.
(func $read_N (param $n i32) (result i32)
  (local $acc i32) (local $w i32)
  (if (i32.and (local.get $n) (i32.const 1)) (then (return (i32.const 0))))
  (local.set $n (i32.load offset=4 (local.get $n)))
  (local.set $w (i32.const 1))
  (block $done
    (loop $next
      (br_if $done (i32.and (local.get $n) (i32.const 1)))
      (if (i32.eqz (i32.and (i32.load (local.get $n)) (i32.const 255)))
        (then (local.set $acc (i32.add (local.get $acc) (local.get $w)))))
      (local.set $w (i32.shl (local.get $w) (i32.const 1)))
      (local.set $n (i32.load offset=4 (local.get $n)))
      (br $next)))
  (i32.add (local.get $acc) (local.get $w)))

;; Reject invalid RFC 3629 encodings before canonical string lifting can trap:
;; overlong sequences, surrogates, truncation, and code points above U+10FFFF.
;; Not constant-time: these strings are not secrets.
(func $utf8_ok (param $p i32) (param $len i32) (result i32)
  (local $i i32) (local $b i32) (local $n i32)
  (local $lo i32) (local $hi i32) (local $j i32)
  (block $end
    (loop $next
      (br_if $end (i32.ge_u (local.get $i) (local.get $len)))
      (local.set $b (i32.load8_u (i32.add (local.get $p) (local.get $i))))
      (if (i32.lt_u (local.get $b) (i32.const 0x80))
        (then
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $next)))
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
              (if (i32.eq (local.get $b) (i32.const 0xE0))
                (then (local.set $lo (i32.const 0xA0))))
              (if (i32.eq (local.get $b) (i32.const 0xED))
                (then (local.set $hi (i32.const 0x9F)))))
            (else
              (if (i32.ge_u (local.get $b) (i32.const 0xF5))
                (then (return (i32.const 0))))
              (local.set $n (i32.const 3))
              (if (i32.eq (local.get $b) (i32.const 0xF0))
                (then (local.set $lo (i32.const 0x90))))
              (if (i32.eq (local.get $b) (i32.const 0xF4))
                (then (local.set $hi (i32.const 0x8F))))))))
      (if (i32.ge_u (i32.add (local.get $i) (local.get $n)) (local.get $len))
        (then (return (i32.const 0))))
      (local.set $b
        (i32.load8_u
          (i32.add (local.get $p) (i32.add (local.get $i) (i32.const 1)))))
      (if (i32.or (i32.lt_u (local.get $b) (local.get $lo))
                  (i32.gt_u (local.get $b) (local.get $hi)))
        (then (return (i32.const 0))))
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
