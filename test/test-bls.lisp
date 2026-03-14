;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; test-bls.lisp - Tests for cl-bls12-381
;;;;
;;;; Basic tests for field arithmetic, curve operations, and BLS signatures.

(defpackage #:cl-bls12-381/test
  (:use #:cl #:cl-bls12-381)
  (:export #:run-tests))

(in-package #:cl-bls12-381/test)

;;; ============================================================================
;;; Test Infrastructure
;;; ============================================================================

(defvar *tests* '())
(defvar *test-failures* 0)
(defvar *test-passes* 0)

(defmacro deftest (name &body body)
  `(progn
     (pushnew ',name *tests*)
     (defun ,name ()
       (handler-case
           (progn ,@body
                  (incf *test-passes*)
                  (format t "  PASS: ~A~%" ',name))
         (error (e)
           (incf *test-failures*)
           (format t "  FAIL: ~A - ~A~%" ',name e))))))

(defun run-tests ()
  "Run all tests."
  (setf *test-failures* 0 *test-passes* 0)
  (format t "~%Running cl-bls12-381 tests...~%~%")
  (dolist (test (reverse *tests*))
    (funcall test))
  (format t "~%Results: ~D passed, ~D failed~%"
          *test-passes* *test-failures*)
  (zerop *test-failures*))

(defmacro assert-true (form &optional msg)
  `(unless ,form
     (error "Assertion failed~@[: ~A~]" ,msg)))

(defmacro assert-equal (a b &optional msg)
  `(unless (equal ,a ,b)
     (error "Expected ~S = ~S~@[: ~A~]" ',a ',b ,msg)))

;;; ============================================================================
;;; Field Arithmetic Tests
;;; ============================================================================

(deftest test-fp-basic
  "Test basic Fp operations."
  (let ((a 12345)
        (b 67890))
    ;; Addition
    (assert-equal (fp-add a b) 80235)
    ;; Subtraction
    (assert-equal (fp-sub b a) 55545)
    ;; Negation
    (assert-equal (fp-add a (fp-neg a)) 0)
    ;; Multiplication
    (assert-equal (fp-mul 2 3) 6)
    ;; Square
    (assert-equal (fp-sqr 5) 25)))

(deftest test-fp-inverse
  "Test Fp multiplicative inverse."
  (let ((a 12345))
    (let ((a-inv (fp-inv a)))
      (assert-equal (fp-mul a a-inv) 1))))

(deftest test-fp-pow
  "Test Fp exponentiation."
  (assert-equal (fp-pow 2 10) 1024)
  (assert-equal (fp-pow 3 5) 243))

(deftest test-fp2-basic
  "Test basic Fp2 operations."
  (let ((a (fp2-make 3 4))
        (b (fp2-make 1 2)))
    ;; Addition
    (let ((sum (fp2-add a b)))
      (assert-equal (fp2-c0 sum) 4)
      (assert-equal (fp2-c1 sum) 6))
    ;; Negation
    (let ((neg-a (fp2-neg a)))
      (let ((zero (fp2-add a neg-a)))
        (assert-equal (fp2-c0 zero) 0)
        (assert-equal (fp2-c1 zero) 0)))))

(deftest test-fp2-mul
  "Test Fp2 multiplication."
  ;; (3 + 4i)(1 + 2i) = 3 + 6i + 4i + 8i^2 = 3 + 10i - 8 = -5 + 10i
  (let* ((a (fp2-make 3 4))
         (b (fp2-make 1 2))
         (prod (fp2-mul a b)))
    (assert-equal (fp2-c0 prod) (fp-sub 0 5))
    (assert-equal (fp2-c1 prod) 10)))

(deftest test-fp2-inverse
  "Test Fp2 multiplicative inverse."
  (let* ((a (fp2-make 3 4))
         (a-inv (fp2-inv a))
         (prod (fp2-mul a a-inv)))
    (assert-equal (fp2-c0 prod) 1)
    (assert-equal (fp2-c1 prod) 0)))

;;; ============================================================================
;;; G1 Curve Tests
;;; ============================================================================

(deftest test-g1-generator-on-curve
  "Test that G1 generator is on the curve."
  (let ((g (g1-generator)))
    (assert-true (g1-on-curve-p g) "G1 generator should be on curve")))

(deftest test-g1-identity
  "Test G1 identity operations."
  (let ((g (g1-generator))
        (o (g1-identity)))
    ;; O + G = G
    (assert-true (g1-equal (g1-add o g) g))
    ;; G + O = G
    (assert-true (g1-equal (g1-add g o) g))
    ;; 0 * G = O
    (assert-true (g1-infinity-p (g1-mul g 0)))))

(deftest test-g1-negation
  "Test G1 point negation."
  (let* ((g (g1-generator))
         (neg-g (g1-neg g))
         (sum (g1-add g neg-g)))
    (assert-true (g1-infinity-p sum) "G + (-G) should be identity")))

(deftest test-g1-double
  "Test G1 point doubling."
  (let* ((g (g1-generator))
         (g2 (g1-double g))
         (g2-alt (g1-add g g)))
    (assert-true (g1-equal g2 g2-alt) "2G via double = G + G")))

(deftest test-g1-scalar-mul
  "Test G1 scalar multiplication."
  (let ((g (g1-generator)))
    ;; 1 * G = G
    (assert-true (g1-equal (g1-mul g 1) g))
    ;; 2 * G = G + G
    (assert-true (g1-equal (g1-mul g 2) (g1-add g g)))
    ;; (a + b) * G = a*G + b*G
    (let ((a 12345)
          (b 67890))
      (assert-true (g1-equal (g1-mul g (+ a b))
                             (g1-add (g1-mul g a) (g1-mul g b)))))))

(deftest test-g1-compress-decompress
  "Test G1 point compression and decompression."
  (let* ((g (g1-generator))
         (compressed (g1-compress g))
         (decompressed (g1-decompress compressed)))
    (assert-equal (length compressed) 48)
    (assert-true (g1-equal g decompressed))))

;;; ============================================================================
;;; G2 Curve Tests
;;; ============================================================================

(deftest test-g2-generator-on-curve
  "Test that G2 generator is on the curve."
  (let ((g (g2-generator)))
    (assert-true (g2-on-curve-p g) "G2 generator should be on curve")))

(deftest test-g2-identity
  "Test G2 identity operations."
  (let ((g (g2-generator))
        (o (g2-identity)))
    (assert-true (g2-infinity-p (g2-add (g2-neg g) g)))))

(deftest test-g2-scalar-mul
  "Test G2 scalar multiplication."
  (let ((g (g2-generator)))
    ;; 2 * G = G + G
    (let ((g2 (g2-mul g 2))
          (g-plus-g (g2-add g g)))
      ;; Compare coordinates
      (let ((x1 (g2-x g2)) (y1 (g2-y g2))
            (x2 (g2-x g-plus-g)) (y2 (g2-y g-plus-g)))
        (assert-equal (fp2-c0 x1) (fp2-c0 x2))
        (assert-equal (fp2-c1 x1) (fp2-c1 x2))
        (assert-equal (fp2-c0 y1) (fp2-c0 y2))
        (assert-equal (fp2-c1 y1) (fp2-c1 y2))))))

;;; ============================================================================
;;; Utility Tests
;;; ============================================================================

(deftest test-bytes-integer-conversion
  "Test byte/integer conversion."
  (let* ((n 123456789012345)
         (bytes (integer-to-bytes n 8 :big-endian t))
         (recovered (bytes-to-integer bytes :big-endian t)))
    (assert-equal n recovered)))

(deftest test-sha256
  "Test SHA-256 hash."
  ;; SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  (let ((empty-hash (sha256 #())))
    (assert-equal (length empty-hash) 32)
    (assert-equal (aref empty-hash 0) #xe3)
    (assert-equal (aref empty-hash 1) #xb0)))

(deftest test-hmac-sha256
  "Test HMAC-SHA256."
  (let ((mac (hmac-sha256 "key" "message")))
    (assert-equal (length mac) 32)))

(deftest test-constant-time-compare
  "Test constant-time byte comparison."
  (let ((a #(1 2 3 4))
        (b #(1 2 3 4))
        (c #(1 2 3 5)))
    (assert-true (constant-time-bytes= a b))
    (assert-true (not (constant-time-bytes= a c)))))

;;; ============================================================================
;;; BLS Signature Tests
;;; ============================================================================

(deftest test-bls-keygen
  "Test BLS key generation."
  (let ((kp (bls-keygen)))
    (assert-true (bls-keypair-p kp))
    (assert-equal (length (bls-keypair-secret kp)) 32)
    (assert-equal (length (bls-keypair-public kp)) 96)))

(deftest test-bls-keygen-deterministic
  "Test deterministic BLS key generation."
  (let ((seed (sha256 "test seed")))
    (let ((kp1 (bls-keygen-deterministic seed))
          (kp2 (bls-keygen-deterministic seed)))
      ;; Same seed should produce same keys
      (assert-true (equalp (bls-keypair-secret kp1) (bls-keypair-secret kp2)))
      (assert-true (equalp (bls-keypair-public kp1) (bls-keypair-public kp2))))))

(deftest test-bls-sign-structure
  "Test BLS signature structure."
  (let* ((kp (bls-keygen))
         (message "Hello, BLS!")
         (sig (bls-sign kp message)))
    (assert-true (bls-signature-p sig))
    (assert-equal (length (bls-signature-point sig)) 48)))

(deftest test-bls-pop
  "Test Proof of Possession generation."
  (let* ((kp (bls-keygen))
         (pop (bls-pop-prove kp)))
    (assert-true (bls-pop-p pop))
    (assert-equal (length (bls-pop-proof pop)) 48)
    (assert-true (equalp (bls-pop-public-key pop) (bls-keypair-public kp)))))

(deftest test-bls-aggregate-signatures
  "Test BLS signature aggregation."
  (let* ((kp1 (bls-keygen))
         (kp2 (bls-keygen))
         (message "Test message")
         (sig1 (bls-sign kp1 message))
         (sig2 (bls-sign kp2 message))
         (agg (bls-aggregate-signatures (list sig1 sig2))))
    (assert-true (bls-aggregate-sig-p agg))
    (assert-equal (length (bls-aggregate-sig-point agg)) 48)
    (assert-equal (bls-aggregate-sig-count agg) 2)))

;;; ============================================================================
;;; Threshold Signature Tests
;;; ============================================================================

(deftest test-threshold-keygen
  "Test threshold key generation."
  (multiple-value-bind (shares master-pk vv) (bls-threshold-keygen 5 3)
    (assert-equal (length shares) 5)
    (assert-equal (length master-pk) 96)
    (assert-equal (length vv) 3)
    (dolist (share shares)
      (assert-true (bls-threshold-share-p share))
      (assert-true (<= 1 (bls-threshold-share-index share) 5)))))

(deftest test-threshold-sign
  "Test threshold partial signing."
  (multiple-value-bind (shares master-pk vv) (bls-threshold-keygen 3 2)
    (declare (ignore master-pk vv))
    (let ((share (first shares))
          (message "Threshold test"))
      (multiple-value-bind (partial-sig index) (bls-threshold-sign share message)
        (assert-equal (length partial-sig) 48)
        (assert-equal index 1)))))

;;; ============================================================================
;;; Run Tests on Load (Optional)
;;; ============================================================================

;; Uncomment to auto-run:
;; (run-tests)
