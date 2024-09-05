#lang racket/base

(provide pre-installer)
(require
 dynext/file
 dynext/link
 racket/file
 racket/system
 setup/dirs)

(define source-repo
  "https://raw.githubusercontent.com/bkc39/XKCP/master")
(define keccak-compact-src-path
  "Standalone/CompactFIPS202/C/Keccak-more-compact.c")

(define (delete-if-exists path)
  (when (file-exists? path)
    (delete-file path)))

(define (pre-installer collections-top-path this-collection-path user-specific?)
  (define private-path
    (build-path this-collection-path "private"))
  (define keccak-source-path
    (build-path private-path "Keccak-more-compact.c"))
  (define wget
    (or (find-executable-path "wget")
        (error 'pre-installer "wget executable not found")))
  (define lib-dir
    (if user-specific? (find-user-lib-dir) (find-lib-dir)))
  (define shared-object-target
    (build-path lib-dir (append-extension-suffix "libkeccak_compact")))

  (make-directory* lib-dir)
  (delete-if-exists shared-object-target)
  (parameterize ([current-directory private-path])
    (delete-if-exists keccak-source-path)
    (system* wget (string-append source-repo "/" keccak-compact-src-path))
    (unless (file-exists? keccak-source-path)
      (error 'pre-installer "wget did not download keccak source file"))

    (parameterize ([current-extension-linker-flags
                    (append
                     (current-extension-linker-flags)
                     (list "-O2" "-fomit-frame-pointer" "-funroll-loops"))]
                   [current-use-mzdyn #f])
      (link-extension #f (list keccak-source-path) shared-object-target))))
