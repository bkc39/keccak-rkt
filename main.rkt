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
  (_fun _uint
        _uint
        (bs : _bytes)
        (_uint64 = (bytes-utf-8-length bs))
        _byte
        _bytes
        _uint64
        -> _void))

(module+ main
  (displayln (format "Keccak Hash: ~a"
                     (Keccak 1088
                             512
                             (string->bytes/utf-8 "")
                             #x06
                             (string->bytes/utf-8 "")
                             38))))
