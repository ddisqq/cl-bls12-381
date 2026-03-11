;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; package.lisp - Package definitions for cl-bls12-381
;;;;
;;;; Exports all public symbols for BLS12-381 operations.

(in-package #:cl-user)

(defpackage #:cl-bls12-381
  (:use #:cl)
  (:nicknames #:bls12-381)
  (:export
   ;; ========================================
   ;; Field Constants
   ;; ========================================
   #:+field-modulus+              ; Prime p for base field Fp
   #:+curve-order+                ; Order r of G1, G2, GT subgroups
   #:+g1-cofactor+                ; Cofactor for G1
   #:+g2-cofactor+                ; Cofactor for G2

   ;; ========================================
   ;; Field Arithmetic (Fp)
   ;; ========================================
   #:fp-add                       ; (a + b) mod p
   #:fp-sub                       ; (a - b) mod p
   #:fp-mul                       ; (a * b) mod p
   #:fp-sqr                       ; a^2 mod p
   #:fp-neg                       ; -a mod p
   #:fp-inv                       ; a^(-1) mod p
   #:fp-pow                       ; a^n mod p
   #:fp-sqrt                      ; Square root in Fp (if exists)
   #:fp-legendre                  ; Legendre symbol (a/p)

   ;; ========================================
   ;; Extension Field Arithmetic (Fp2)
   ;; ========================================
   #:fp2-add
   #:fp2-sub
   #:fp2-mul
   #:fp2-sqr
   #:fp2-neg
   #:fp2-inv
   #:fp2-conjugate
   #:fp2-frobenius

   ;; ========================================
   ;; Extension Field Arithmetic (Fp12)
   ;; ========================================
   #:fp12-add
   #:fp12-sub
   #:fp12-mul
   #:fp12-sqr
   #:fp12-inv
   #:fp12-conjugate
   #:fp12-frobenius

   ;; ========================================
   ;; G1 Curve Operations
   ;; ========================================
   #:g1-generator                 ; Standard generator point
   #:g1-identity                  ; Point at infinity
   #:g1-add                       ; Point addition
   #:g1-double                    ; Point doubling
   #:g1-neg                       ; Point negation
   #:g1-mul                       ; Scalar multiplication
   #:g1-on-curve-p                ; Point validation
   #:g1-in-subgroup-p             ; Subgroup membership
   #:g1-compress                  ; Compress to 48 bytes
   #:g1-decompress                ; Decompress from 48 bytes
   #:g1-hash-to-curve             ; Hash-to-curve (SSWU)

   ;; ========================================
   ;; G2 Curve Operations
   ;; ========================================
   #:g2-generator                 ; Standard generator point
   #:g2-identity                  ; Point at infinity
   #:g2-add                       ; Point addition
   #:g2-double                    ; Point doubling
   #:g2-neg                       ; Point negation
   #:g2-mul                       ; Scalar multiplication
   #:g2-on-curve-p                ; Point validation
   #:g2-in-subgroup-p             ; Subgroup membership
   #:g2-compress                  ; Compress to 96 bytes
   #:g2-decompress                ; Decompress from 96 bytes
   #:g2-hash-to-curve             ; Hash-to-curve (SSWU)

   ;; ========================================
   ;; Pairing Operations
   ;; ========================================
   #:pairing                      ; e: G1 x G2 -> GT
   #:pairing-check                ; Product of pairings = 1?
   #:miller-loop                  ; Miller loop computation
   #:final-exponentiation         ; Final exp in pairing

   ;; ========================================
   ;; BLS Signature Types
   ;; ========================================
   #:bls-keypair
   #:bls-keypair-p
   #:bls-keypair-secret
   #:bls-keypair-public
   #:bls-signature
   #:bls-signature-p
   #:bls-signature-point
   #:bls-aggregate-sig
   #:bls-aggregate-sig-p
   #:bls-threshold-share
   #:bls-threshold-share-p
   #:bls-pop
   #:bls-pop-p

   ;; ========================================
   ;; BLS Key Generation
   ;; ========================================
   #:bls-keygen                   ; Random keypair
   #:bls-keygen-deterministic     ; Keypair from seed
   #:bls-derive-public            ; Derive PK from SK

   ;; ========================================
   ;; BLS Signing & Verification
   ;; ========================================
   #:bls-sign                     ; Sign message
   #:bls-sign-with-dst            ; Sign with custom DST
   #:bls-verify                   ; Verify signature
   #:bls-verify-with-dst          ; Verify with custom DST

   ;; ========================================
   ;; BLS Aggregation
   ;; ========================================
   #:bls-aggregate-signatures     ; Aggregate sigs
   #:bls-aggregate-public-keys    ; Aggregate PKs
   #:bls-verify-aggregate         ; Verify aggregate
   #:bls-safe-aggregate           ; Rogue-key-safe aggregation

   ;; ========================================
   ;; BLS Batch Verification
   ;; ========================================
   #:bls-batch-verify             ; Batch verify tuples
   #:bls-batch-verify-same-message ; Optimized same-msg batch

   ;; ========================================
   ;; Proof of Possession
   ;; ========================================
   #:bls-pop-prove                ; Generate PoP
   #:bls-pop-verify               ; Verify PoP
   #:bls-aggregate-with-pop       ; Safe aggregation with PoP

   ;; ========================================
   ;; Threshold Signatures
   ;; ========================================
   #:bls-threshold-keygen         ; Generate shares
   #:bls-threshold-sign           ; Partial signature
   #:bls-threshold-combine        ; Combine partials
   #:bls-threshold-verify         ; Verify threshold sig

   ;; ========================================
   ;; Domain Separation Tags
   ;; ========================================
   #:+dst-sign+                   ; Standard signing DST
   #:+dst-pop+                    ; PoP DST

   ;; ========================================
   ;; Utilities
   ;; ========================================
   #:bytes-to-integer
   #:integer-to-bytes
   #:constant-time-bytes=
   #:get-random-bytes
   #:sha256
   #:hmac-sha256))
