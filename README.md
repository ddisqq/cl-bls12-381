# cl-bls12-381

Pure Common Lisp implementation of the BLS12-381 pairing-friendly elliptic curve.

## Features

- **Field Arithmetic**: Fp, Fp2, Fp6, Fp12 tower extensions
- **Curve Operations**: G1 and G2 point arithmetic (add, double, scalar multiply)
- **Pairing**: Optimal ate pairing with Miller loop and final exponentiation
- **BLS Signatures**: Sign, verify, aggregate, batch verify
- **Threshold Signatures**: t-of-n threshold BLS via Shamir secret sharing
- **Proof of Possession**: Rogue key attack prevention
- **Hash-to-Curve**: RFC 9380 compliant (simplified SSWU)

## Requirements

- SBCL (tested) or other ANSI Common Lisp implementation
- ASDF

## Installation

```lisp
(asdf:load-system :cl-bls12-381)
```

## Quick Start

```lisp
(in-package :cl-bls12-381)

;; Generate keypair
(defvar *kp* (bls-keygen))

;; Sign message
(defvar *sig* (bls-sign *kp* "Hello, BLS!"))

;; Verify signature
(bls-verify (bls-keypair-public *kp*) "Hello, BLS!" *sig*)
;; => T

;; Aggregate signatures
(let* ((kp1 (bls-keygen))
       (kp2 (bls-keygen))
       (msg "Same message")
       (sig1 (bls-sign kp1 msg))
       (sig2 (bls-sign kp2 msg))
       (agg (bls-aggregate-signatures (list sig1 sig2))))
  (bls-verify-aggregate (list (bls-keypair-public kp1)
                              (bls-keypair-public kp2))
                        msg agg))
;; => T
```

## API Reference

### Key Generation

```lisp
(bls-keygen) => bls-keypair
(bls-keygen-deterministic seed &optional info) => bls-keypair
(bls-derive-public secret-key) => public-key-bytes
```

### Signing & Verification

```lisp
(bls-sign keypair message) => bls-signature
(bls-sign-with-dst keypair message dst) => bls-signature
(bls-verify public-key message signature) => boolean
(bls-verify-with-dst public-key message signature dst) => boolean
```

### Aggregation

```lisp
(bls-aggregate-signatures signatures) => bls-aggregate-sig
(bls-aggregate-public-keys public-keys) => aggregated-pk
(bls-verify-aggregate public-keys message aggregate-sig) => boolean
(bls-safe-aggregate public-keys signatures) => bls-aggregate-sig
```

### Proof of Possession

```lisp
(bls-pop-prove keypair) => bls-pop
(bls-pop-verify pop) => boolean
(bls-aggregate-with-pop keypairs-with-pops) => aggregated-pk
```

### Threshold Signatures

```lisp
(bls-threshold-keygen n threshold) => (values shares master-pk verification-vector)
(bls-threshold-sign share message) => (values partial-sig index)
(bls-threshold-combine partial-sigs indices threshold) => bls-signature
(bls-threshold-verify master-pk message signature) => boolean
```

### Low-Level Operations

#### Field Arithmetic (Fp)
```lisp
fp-add fp-sub fp-mul fp-sqr fp-neg fp-inv fp-pow fp-sqrt
```

#### Field Extensions (Fp2, Fp12)
```lisp
fp2-add fp2-sub fp2-mul fp2-sqr fp2-neg fp2-inv fp2-conjugate
fp12-add fp12-sub fp12-mul fp12-sqr fp12-inv
```

#### Curve Operations (G1, G2)
```lisp
g1-add g1-double g1-neg g1-mul g1-compress g1-decompress g1-hash-to-curve
g2-add g2-double g2-neg g2-mul g2-compress g2-decompress
```

#### Pairing
```lisp
(pairing g1-point g2-point) => gt-element
(pairing-check p1 q1 p2 q2 ...) => boolean
```

## Constants

- `+field-modulus+`: BLS12-381 base field prime p (381 bits)
- `+curve-order+`: Subgroup order r (~255 bits, 128-bit security)
- `+dst-sign+`: Domain separation tag for signing
- `+dst-pop+`: Domain separation tag for Proof of Possession

## Security

- **128-bit security level**
- **Deterministic signatures**: No nonce vulnerabilities
- **Rogue key protection**: Via PoP or coefficient-weighted aggregation
- **Constant-time comparisons**: For secret data

## Standards Compliance

- IETF draft-irtf-cfrg-bls-signature-05
- IETF draft-irtf-cfrg-hash-to-curve-16 (RFC 9380)
- Ethereum 2.0 BLS specification

## Testing

```lisp
(asdf:test-system :cl-bls12-381)
;; or
(cl-bls12-381/test:run-tests)
```

## License

MIT License. See LICENSE file.

## Acknowledgments

Extracted from the CLPIC project. Based on BLS12-381 curve parameters by
Sean Bowe (Zcash).
