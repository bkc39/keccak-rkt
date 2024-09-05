#lang racket/base

(require
 ffi/unsafe
 ffi/unsafe/define
 ffi/unsafe/define/conventions
 openssl/sha1)

(module+ test
  (require rackunit))

(define-ffi-definer define-XKCP-keccak
  (ffi-lib "libkeccak_compact")
  #:make-c-id convention:hyphen->underscore)

;; void Keccak(ui r, ui c, const u8 *in, u64 inLen, u8 sfx, u8 *out, u64 outLen)
(define-XKCP-keccak Keccak
  (_fun _uint
        _uint
        [bs : (_list i _byte)]
        [_uint64 = (length bs)]
        _byte
        [hashed : (_list o _byte n)]
        [n : _uint64]
        -> _void
        -> (apply bytes hashed)))

(module+ main
  (displayln (format "Keccak Hash: ~a"
                     (bytes->hex-string
                      (Keccak 1088
                              512
                              (bytes 0 0 0)
                              #x06
                              32)))))
