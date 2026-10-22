;; Template expanded from common.wat by expand.mjs with shared heap and
;; UTF-8 helpers. Email strings must be validated before canonical ABI lifting.
(module
  (import "rocq" "memory" (memory 1))
  (import "rocq" "mem_ptr" (global $mem_ptr (mut i32)))
  (import "rocq" "out_of_mem" (global $out_of_mem (mut i32)))
  (import "rocq" "result" (global $result (mut i32)))
  (import "authentikate:email/sender@0.1.0" "send"
    (func $send
      (param i32 i32)       ;; from: string
      (param i32 i32)       ;; to: list<string>
      (param i32 i32)       ;; subject: string
      (param i32 i32)       ;; text: string
      (param i32 i32 i32)   ;; idempotency-key: option<string>
      (param i32)))         ;; result<_, error>: 16-byte return area
  (global $buf_len (mut i32) (i32.const 0))
  ;; @COMMON alloc list_len lower utf8_ok@

  (func $email-send (param $from i32) (param $to i32)
                    (param $subject i32) (param $text i32) (result i32)
    (local $fp i32) (local $fn i32) (local $tp i32) (local $tn i32)
    (local $sp i32) (local $sn i32) (local $bp i32) (local $bn i32)
    (local $recipients i32) (local $ret i32)
    (local.set $fp (call $lower (local.get $from)))
    (local.set $fn (global.get $buf_len))
    (local.set $tp (call $lower (local.get $to)))
    (local.set $tn (global.get $buf_len))
    (local.set $sp (call $lower (local.get $subject)))
    (local.set $sn (global.get $buf_len))
    (local.set $bp (call $lower (local.get $text)))
    (local.set $bn (global.get $buf_len))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (if (i32.eqz (i32.and
          (i32.and (call $utf8_ok (local.get $fp) (local.get $fn))
                   (call $utf8_ok (local.get $tp) (local.get $tn)))
          (i32.and (call $utf8_ok (local.get $sp) (local.get $sn))
                   (call $utf8_ok (local.get $bp) (local.get $bn)))))
      (then (return (i32.const 1))))
    (local.set $recipients (call $alloc (i32.const 8) (i32.const 4)))
    (local.set $ret (call $alloc (i32.const 16) (i32.const 4)))
    (if (global.get $out_of_mem) (then (return (i32.const 1))))
    (i32.store (local.get $recipients) (local.get $tp))
    (i32.store offset=4 (local.get $recipients) (local.get $tn))
    (call $send
      (local.get $fp) (local.get $fn)
      (local.get $recipients) (i32.const 1)
      (local.get $sp) (local.get $sn) (local.get $bp) (local.get $bn)
      (i32.const 0) (i32.const 0) (i32.const 0) (local.get $ret))
    (if (i32.load8_u (local.get $ret)) (then (return (i32.const 1))))
    (i32.const 3)) ;; Immediate true (accepted); every refusal above is false (1).

  ;; Force argument plus four Rocq byte strings. The inspected result keeps the
  ;; foreign effect live through extraction and optimization.
  (func (export "ffi_email_send") (param $force i32) (param $from i32)
        (param $to i32) (param $subject i32) (param $text i32)
    (global.set $result (call $email-send
      (local.get $from) (local.get $to) (local.get $subject) (local.get $text))))
)
