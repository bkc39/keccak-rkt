#lang racket/base

(provide
 bytes->hex-string
 hex-string->bytes
 Keccak
 FIPS202-SHAKE128
 FIPS202-SHAKE256
 FIPS202-SHA3-224
 FIPS202-SHA3-256
 FIPS202-SHA3-384
 FIPS202-SHA3-512)

(require
 ffi/unsafe
 ffi/unsafe/define
 ffi/unsafe/define/conventions
 openssl/sha1
 syntax/parse/define
 (for-syntax racket/base racket/syntax))

(module+ test
  (require rackunit))

(define-ffi-definer define-XKCP-keccak
  (ffi-lib "libkeccak_compact")
  #:make-c-id convention:hyphen->underscore)

(define-XKCP-keccak Keccak
  (_fun _uint
        _uint
        [bs : _bytes]
        [_uint64 = (bytes-length bs)]
        _byte
        [hashed : (_bytes o n)]
        [n : _uint64]
        -> _void
        -> hashed))

(module+ test
  (check-equal?
   (Keccak 1088
           512
           #""
           #x06
           32)
   (hex-string->bytes
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")))

(define-XKCP-keccak FIPS202-SHAKE128
  (_fun [bs : _bytes]
        [_uint64 = (bytes-length bs)]
        [hashed : (_bytes o n)]
        [n : _uint64]
        -> _void
        -> hashed))

(module+ test
  (check-pred bytes? (FIPS202-SHAKE128 #"" 32))

  (check-equal?
   (FIPS202-SHAKE128 #"" 32)
   (Keccak 1344 256 #"" #x1F 32)))


(define-XKCP-keccak FIPS202-SHAKE256
  (_fun [bs : _bytes]
        [_uint64 = (bytes-length bs)]
        [hashed : (_bytes o n)]
        [n : _uint64]
        -> _void
        -> hashed))

(module+ test
  (check-pred bytes? (FIPS202-SHAKE256 #"" 64))

  (check-equal?
   (FIPS202-SHAKE256 #"" 64)
   (Keccak 1088 512 #"" #x1F 64)))

(define-syntax-parser define-sha3/size
  [(_ n:exact-positive-integer)
   #:with name (format-id #'n "FIPS202-SHA3-~a" #'n)
   #`(define-XKCP-keccak name
       (_fun [bs : _bytes]
             [_uint64 = (bytes-length bs)]
             [hashed : (_bytes o #,(/ (syntax->datum #'n) 8))]
             -> _void
             -> hashed))])

(define-sha3/size 224)
(define-sha3/size 256)
(define-sha3/size 384)
(define-sha3/size 512)

(module+ test
  (check-pred bytes? (FIPS202-SHA3-224 #""))
  (check-pred bytes? (FIPS202-SHA3-256 #""))
  (check-pred bytes? (FIPS202-SHA3-384 #""))
  (check-pred bytes? (FIPS202-SHA3-512 #""))

  (check-equal?
   (FIPS202-SHA3-224 #"")
   (Keccak 1152 448 #"" #x06 28))

  (check-equal?
   (FIPS202-SHA3-256 #"")
   (Keccak 1088 512 #"" #x06 32))

  (check-equal?
   (FIPS202-SHA3-384 #"")
   (Keccak 832 768 #"" #x06 48))

  (check-equal?
   (FIPS202-SHA3-512 #"")
   (Keccak 576 1024 #"" #x06 64)))

(define (keccak256 obj)
  (define bytes-to-hash
    (cond
      [(string? obj)
       (string->bytes/utf-8 obj)]
      [(list? obj)
       (apply bytes obj)]
      [(vector? obj)
       (apply bytes (vector->list obj))]
      [else
       (error 'keccak256 "Invalid object: ~a" obj)]))
  (FIPS202-SHA3-256 bytes-to-hash))

(module+ test
  (check-equal?
   (keccak256 "")
   (FIPS202-SHA3-256 #"")))
