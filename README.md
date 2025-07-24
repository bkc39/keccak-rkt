keccak-rkt
=========

Racket bindings to [XKCP](https://github.com/XKCP/XKCP)
implementation of the `keccak` family of hash functions. These hashes
should match those used in [Solidity function
selectors](https://docs.soliditylang.org/en/develop/abi-spec.html#function-selector).

__Note:__ These hashes **do not** match those produced by the Racket
[crypto](https://docs.racket-lang.org/crypto/index.html) library's
`sha3` digest.

```racket
> (require crypto crypto/libcrypto keccak)
> (crypto-factories libcrypto-factory)
> (subbytes (digest 'sha3-256 #"") 0 4)
#"\247\377\306\370"
> (subbytes (keccak256 #"") 0 4)
#"\305\322F\1"
```

Other low level bindings to the FIPS202 hash function are also exported

* `Keccak`
* `FIPS202-SHAKE128`
* `FIPS202-SHAKE256`
* `FIPS202-SHA3-224`
* `FIPS202-SHA3-256`
* `FIPS202-SHA3-384`
* `FIPS202-SHA3-512`
