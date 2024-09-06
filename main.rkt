#lang racket/base

(provide
 ;; racket interface
 shake128
 shake256
 keccak224
 keccak256
 keccak384
 keccak512

 keccak

 bytes->hex-string
 hex-string->bytes

 ;; foreign bindings
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

(define (convert-to-bytes obj [who 'convert-to-bytes])
  (cond
    [(bytes? obj)
     obj]
    [(string? obj)
     (string->bytes/utf-8 obj)]
    [else
     (error who "string or bytes expected. got: ~a" obj)]))

(define (keccak r c str-or-bytes sfx out-len)
  (Keccak r c (convert-to-bytes str-or-bytes) sfx out-len))

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



(begin-for-syntax
  (define-syntax-class wrapper-arg
    #:attributes (decl-stx body-stx)
    (pattern n:id
             #:attr decl-stx #'n
             #:attr body-stx #'n)
    (pattern (n:id e:expr)
             #:attr decl-stx #'(n e)
             #:attr body-stx #'n)))

(define-syntax-parse-rule
  (define-string-wrapper
    (wrapper-name:id args*:wrapper-arg ...) (~datum <=) ffi-name:id)
  (define (wrapper-name str-or-bytes args*.decl-stx ...)
    (ffi-name (convert-to-bytes str-or-bytes) args*.body-stx ...)))

(define-string-wrapper (shake128 [n 32]) <= FIPS202-SHAKE128)

(module+ test
  (check-equal?
   (shake128 #"apple" 32)
   (FIPS202-SHAKE128 #"apple" 32))

  (check-equal?
   (shake128 #"apple")
   (shake128 #"apple" 32))

  (check-equal?
   (shake128 "apple" 32)
   (shake128 #"apple" 32)))

(define-string-wrapper (shake256 n) <= FIPS202-SHAKE256)

(define-string-wrapper (keccak224) <= FIPS202-SHA3-224)
(define-string-wrapper (keccak256) <= FIPS202-SHA3-256)
(define-string-wrapper (keccak384) <= FIPS202-SHA3-384)
(define-string-wrapper (keccak512) <= FIPS202-SHA3-512)

(module+ test
  (check-equal?
   (keccak256 "")
   (FIPS202-SHA3-256 #"")))
