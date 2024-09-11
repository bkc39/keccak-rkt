#lang scribble/manual

@require[@for-label[keccak
                    racket/base
                    (except-in crypto
                               bytes->hex-string) ]]

@title{keccak}
@author{bkc}

@defmodule[keccak]

Racket bindings to the @hyperlink["https://github.com/XKCP/XKCP"]{XKCP}
implementation of the
@hyperlink["https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf"]{FIPS-202}
SHA-3 hash functions. This implements the Keccak hash function that should match
those used to calculate function selectors
@hyperlink[
 "https://docs.soliditylang.org/en/develop/abi-spec.html#function-selector"
 ]{Solidity}

@bold{Note}: @racket[keccak256] is @bold{NOT} the same as what is in the
@racket[crypto] library.

@section{Exposed Hash Functions}
