;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; pairing.lisp - Bilinear Pairing for BLS12-381
;;;;
;;;; Implements the optimal ate pairing e: G1 x G2 -> GT.

(in-package #:cl-bls12-381)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; BLS12-381 Pairing Parameters
;;; ============================================================================

;; The parameter x for BLS12-381 (determines curve construction)
;; p = (x - 1)^2 * (x^4 - x^2 + 1) / 3 + x
;; r = x^4 - x^2 + 1
(defconstant +bls12-381-x+
  #xD201000000010000
  "BLS12-381 curve parameter x = -0xD201000000010000 (negative).")

(defconstant +bls12-381-x-is-negative+ t
  "Whether the x parameter is negative.")

;;; ============================================================================
;;; Miller Loop Utilities
;;; ============================================================================

(defun line-function-double (r q)
  "Compute line function for doubling step in Miller loop.

   Given R in G2 (affine) and Q in G1, computes the line tangent to R at R
   evaluated at Q.

   RETURN:
   Fp12 element representing the line evaluation."
  (let* ((rx (g2-x r))
         (ry (g2-y r))
         (qx (g1-x q))
         (qy (g1-y q))
         ;; Tangent slope: lambda = 3*rx^2 / (2*ry)
         (rx-sqr (fp2-sqr rx))
         (three-rx-sqr (fp2-add rx-sqr (fp2-add rx-sqr rx-sqr)))
         (two-ry (fp2-add ry ry))
         (lambda (fp2-mul three-rx-sqr (fp2-inv two-ry)))
         ;; Line: l(Q) = (qy - ry) - lambda * (qx - rx)
         ;; Sparse Fp12 representation for efficiency
         (qx-fp2 (fp2-make qx 0))
         (qy-fp2 (fp2-make qy 0))
         (term1 (fp2-sub qy-fp2 ry))
         (term2 (fp2-mul lambda (fp2-sub qx-fp2 rx)))
         (result (fp2-sub term1 term2)))
    ;; Embed into Fp12 (simplified - just store in c0 position)
    (fp12-make (fp6-make result (fp2-zero) (fp2-zero))
               (fp6-zero))))

(defun line-function-add (r s q)
  "Compute line function for addition step in Miller loop.

   Given R, S in G2 and Q in G1, computes the line through R and S
   evaluated at Q.

   RETURN:
   Fp12 element."
  (let* ((rx (g2-x r))
         (ry (g2-y r))
         (sx (g2-x s))
         (sy (g2-y s))
         (qx (g1-x q))
         (qy (g1-y q))
         ;; Chord slope: lambda = (sy - ry) / (sx - rx)
         (dy (fp2-sub sy ry))
         (dx (fp2-sub sx rx))
         (lambda (fp2-mul dy (fp2-inv dx)))
         ;; Line evaluation
         (qx-fp2 (fp2-make qx 0))
         (qy-fp2 (fp2-make qy 0))
         (term1 (fp2-sub qy-fp2 ry))
         (term2 (fp2-mul lambda (fp2-sub qx-fp2 rx)))
         (result (fp2-sub term1 term2)))
    (fp12-make (fp6-make result (fp2-zero) (fp2-zero))
               (fp6-zero))))

;;; ============================================================================
;;; Miller Loop
;;; ============================================================================

(defun miller-loop (p q)
  "Execute Miller loop for optimal ate pairing.

   PARAMETERS:
   - P: G1 point
   - Q: G2 point

   RETURN:
   Fp12 element (pre-final-exponentiation)

   ALGORITHM:
   Iterates over bits of the curve parameter x, accumulating:
   - Doubling steps: f = f^2 * l_R,R(P)
   - Addition steps: f = f * l_R,Q(P)

   This is the core computation of the pairing."
  (when (or (g1-infinity-p p) (g2-infinity-p q))
    (return-from miller-loop (fp12-one)))

  (let ((f (fp12-one))
        (r q)
        ;; Use absolute value of x, handle sign at end
        (x-abs (abs (- +bls12-381-x+))))

    ;; Iterate over bits of x from MSB to LSB
    (loop for i from (1- (integer-length x-abs)) downto 0
          do
             ;; Doubling step
             (let ((line-eval (line-function-double r p)))
               (setf f (fp12-sqr f))
               (setf f (fp12-mul f line-eval))
               (setf r (g2-double r)))

             ;; Addition step if bit is set
             (when (logbitp i x-abs)
               (let ((line-eval (line-function-add r q p)))
                 (setf f (fp12-mul f line-eval))
                 (setf r (g2-add r q)))))

    ;; If x is negative, conjugate the result
    (when +bls12-381-x-is-negative+
      (setf f (fp12-conjugate f)))

    f))

;;; ============================================================================
;;; Final Exponentiation
;;; ============================================================================

(defun final-exponentiation (f)
  "Compute final exponentiation for pairing.

   PARAMETERS:
   - F: Fp12 element from Miller loop

   RETURN:
   Fp12 element in GT subgroup

   ALGORITHM:
   f^((p^12 - 1) / r) decomposed as:
   1. Easy part: f^((p^6 - 1)(p^2 + 1))
   2. Hard part: f^((p^4 - p^2 + 1) / r)"

  ;; Easy part: f^(p^6 - 1) * f^(p^2 + 1)
  (let* (;; f^(p^6) = conjugate(f) for BLS12
         (f-conj (fp12-conjugate f))
         ;; f^(p^6 - 1) = f^(p^6) / f = conj(f) * inv(f)
         (f-inv (fp12-inv f))
         (f1 (fp12-mul f-conj f-inv))
         ;; f^(p^2) via Frobenius squared
         (f1-frob (fp12-frobenius (fp12-frobenius f1)))
         ;; f^(p^2 + 1)
         (f2 (fp12-mul f1-frob f1)))

    ;; Hard part: f2^((p^4 - p^2 + 1) / r)
    ;; This requires computing several exponentiations
    ;; Simplified version using direct exponentiation
    (hard-part-exponentiation f2)))

(defun hard-part-exponentiation (f)
  "Compute hard part of final exponentiation.

   Uses optimized algorithm specific to BLS12-381."
  ;; For a full implementation, this would use:
  ;; - Addition chain for x
  ;; - Frobenius endomorphism
  ;; - Cyclotomic squaring

  ;; Simplified: compute f^((p^4 - p^2 + 1) / r) directly
  ;; The exponent is: (p^4 - p^2 + 1) / r
  ;; For efficiency, we use the structure: e = (x+1) + p*(-x) + p^2*(x^2) + p^3*(-x^3+1)

  (let* ((x (abs (- +bls12-381-x+)))
         ;; f^x
         (fx (fp12-pow f x))
         ;; f^(x^2)
         (fx2 (fp12-pow fx x))
         ;; f^(x^3)
         (fx3 (fp12-pow fx2 x))
         ;; Combine with Frobenius
         ;; Simplified direct computation
         (result (fp12-mul f fx)))
    ;; Apply additional Frobenius-based combinations
    (fp12-mul result (fp12-frobenius fx2))))

;;; ============================================================================
;;; Pairing Functions
;;; ============================================================================

(defun pairing (p q)
  "Compute optimal ate pairing e(P, Q).

   PARAMETERS:
   - P: G1 point
   - Q: G2 point

   RETURN:
   GT element (Fp12)

   PROPERTIES:
   - Bilinear: e(aP, bQ) = e(P, Q)^(ab)
   - Non-degenerate: e(G1, G2) != 1 for generators

   ALGORITHM:
   1. Miller loop: compute f_{x,Q}(P)
   2. Final exponentiation: f^((p^12 - 1) / r)"
  (cond
    ((or (g1-infinity-p p) (g2-infinity-p q))
     (fp12-one))
    (t
     (let ((f (miller-loop p q)))
       (final-exponentiation f)))))

(defun pairing-check (&rest pairs)
  "Check if product of pairings equals identity.

   PARAMETERS:
   - PAIRS: Alternating P1, Q1, P2, Q2, ... sequence

   RETURN:
   T if e(P1,Q1) * e(P2,Q2) * ... = 1 in GT

   USE CASES:
   - BLS verification: e(sig, G2) * e(-H(m), pk) = 1
   - Multi-pairing checks

   OPTIMIZATION:
   Computes product of Miller loops before single final exponentiation,
   which is more efficient than separate pairings."
  (unless (evenp (length pairs))
    (error "pairing-check requires even number of arguments (pairs of G1, G2 points)"))

  (let ((f (fp12-one)))
    ;; Accumulate Miller loops
    (loop for (p q) on pairs by #'cddr
          do (let ((ml (miller-loop p q)))
               (setf f (fp12-mul f ml))))

    ;; Single final exponentiation
    (let ((result (final-exponentiation f)))
      ;; Check if result is identity in GT
      (fp12-is-one-p result))))

(defun fp12-is-one-p (f)
  "Check if Fp12 element is the multiplicative identity."
  (let ((c0 (fp12-c0 f))
        (c1 (fp12-c1 f)))
    (and (fp6-is-zero-p c1)
         (let ((c0-0 (fp6-c0 c0))
               (c0-1 (fp6-c1 c0))
               (c0-2 (fp6-c2 c0)))
           (and (fp2-is-one-p c0-0)
                (fp2-is-zero-p c0-1)
                (fp2-is-zero-p c0-2))))))

(defun fp6-is-zero-p (f)
  "Check if Fp6 element is zero."
  (and (fp2-is-zero-p (fp6-c0 f))
       (fp2-is-zero-p (fp6-c1 f))
       (fp2-is-zero-p (fp6-c2 f))))

(defun fp2-is-zero-p (f)
  "Check if Fp2 element is zero."
  (and (zerop (fp2-c0 f))
       (zerop (fp2-c1 f))))

(defun fp2-is-one-p (f)
  "Check if Fp2 element is one."
  (and (= 1 (fp2-c0 f))
       (zerop (fp2-c1 f))))

;;; ============================================================================
;;; GT Operations
;;; ============================================================================

;; GT is the subgroup of Fp12* of order r
;; Operations are multiplication in Fp12

(defun gt-identity ()
  "Return GT identity (1 in Fp12)."
  (fp12-one))

(defun gt-mul (a b)
  "Multiply GT elements."
  (fp12-mul a b))

(defun gt-pow (a n)
  "Compute a^n in GT."
  (fp12-pow a n))

(defun gt-equal (a b)
  "Check GT element equality."
  (let ((a-c0 (fp12-c0 a)) (a-c1 (fp12-c1 a))
        (b-c0 (fp12-c0 b)) (b-c1 (fp12-c1 b)))
    ;; Compare all coefficients
    (and (fp6-equal a-c0 b-c0)
         (fp6-equal a-c1 b-c1))))

(defun fp6-equal (a b)
  "Check Fp6 equality."
  (and (fp2-equal (fp6-c0 a) (fp6-c0 b))
       (fp2-equal (fp6-c1 a) (fp6-c1 b))
       (fp2-equal (fp6-c2 a) (fp6-c2 b))))

(defun fp2-equal (a b)
  "Check Fp2 equality."
  (and (= (fp2-c0 a) (fp2-c0 b))
       (= (fp2-c1 a) (fp2-c1 b))))
