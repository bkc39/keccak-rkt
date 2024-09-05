#lang racket/base

(require
 ffi/unsafe
 ffi/unsafe/define
 ffi/unsafe/define/conventions)

(module+ test
  (require rackunit))

(define-ffi-definer define-XKCP-keccak
  (ffi-lib "libkeccak_compact")
  #:make-c-id convention:hyphen->underscore)

;; void Keccak(ui r, ui c, const u8 *in, u64 inLen, u8 sfx, u8 *out, u64 outLen)
(define-XKCP-keccak Keccak
  (_fun _byte _byte _bytes _uint64 -> _int))
