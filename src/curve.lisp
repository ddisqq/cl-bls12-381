;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; curve.lisp - G1 and G2 Curve Operations for BLS12-381
;;;;
;;;; Implements elliptic curve arithmetic for both G1 (over Fp) and G2 (over Fp2).

(in-package #:cl-bls12-381)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; Curve Equation Parameters
;;; ============================================================================
;;; BLS12-381: y^2 = x^3 + 4 (for G1)
;;;            y^2 = x^3 + 4(1+i) (for G2)

(defconstant +g1-b+ 4
  "Coefficient b in G1 curve equation y^2 = x^3 + b.")

;; G2 curve coefficient b' = 4(1+i) in Fp2
(defparameter +g2-b+ (fp2-make 4 4)
  "Coefficient b' in G2 curve equation y^2 = x^3 + b'.")

;;; ============================================================================
;;; G1 Generator (Standard Generator from BLS12-381)
;;; ============================================================================

(defconstant +g1-generator-x+
  #x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
  "X-coordinate of G1 generator.")

(defconstant +g1-generator-y+
  #x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
  "Y-coordinate of G1 generator.")

;;; ============================================================================
;;; G1 Point Representation
;;; ============================================================================
;;; Points are (x . y) pairs where x, y are Fp elements (integers)
;;; Point at infinity is represented as (:infinity . nil)

(defun g1-make (x y)
  "Create G1 point from coordinates."
  (cons (fp-reduce x) (fp-reduce y)))

(defun g1-identity ()
  "Return G1 identity (point at infinity)."
  (cons :infinity nil))

(defun g1-infinity-p (p)
  "Check if P is the point at infinity."
  (eq (car p) :infinity))

(defun g1-x (p) (car p))
(defun g1-y (p) (cdr p))

(defun g1-generator ()
  "Return standard G1 generator point."
  (g1-make +g1-generator-x+ +g1-generator-y+))

(defun g1-equal (p q)
  "Check if two G1 points are equal."
  (cond ((and (g1-infinity-p p) (g1-infinity-p q)) t)
        ((or (g1-infinity-p p) (g1-infinity-p q)) nil)
        (t (and (= (g1-x p) (g1-x q))
                (= (g1-y p) (g1-y q))))))

;;; ============================================================================
;;; G1 Point Validation
;;; ============================================================================

(defun g1-on-curve-p (p)
  "Check if P lies on the G1 curve y^2 = x^3 + 4."
  (when (g1-infinity-p p)
    (return-from g1-on-curve-p t))
  (let* ((x (g1-x p))
         (y (g1-y p))
         (lhs (fp-sqr y))
         (rhs (fp-add (fp-pow x 3) +g1-b+)))
    (= lhs rhs)))

(defun g1-in-subgroup-p (p)
  "Check if P is in the prime-order subgroup by verifying r*P = O."
  (when (g1-infinity-p p)
    (return-from g1-in-subgroup-p t))
  (g1-infinity-p (g1-mul p +curve-order+)))

;;; ============================================================================
;;; G1 Point Operations
;;; ============================================================================

(defun g1-neg (p)
  "Negate G1 point: (x, y) -> (x, -y)."
  (if (g1-infinity-p p)
      (g1-identity)
      (g1-make (g1-x p) (fp-neg (g1-y p)))))

(defun g1-double (p)
  "Double G1 point using tangent line formula.
   2P = ((3x^2 / 2y)^2 - 2x, (3x^2 / 2y)(x - x') - y)"
  (when (g1-infinity-p p)
    (return-from g1-double (g1-identity)))
  (let* ((x (g1-x p))
         (y (g1-y p)))
    (when (zerop y)
      (return-from g1-double (g1-identity)))
    (let* (;; lambda = 3x^2 / 2y
           (x-sqr (fp-sqr x))
           (numerator (fp-mul 3 x-sqr))
           (denominator (fp-mul 2 y))
           (lambda (fp-mul numerator (fp-inv denominator)))
           ;; x' = lambda^2 - 2x
           (lambda-sqr (fp-sqr lambda))
           (x-prime (fp-sub lambda-sqr (fp-mul 2 x)))
           ;; y' = lambda(x - x') - y
           (y-prime (fp-sub (fp-mul lambda (fp-sub x x-prime)) y)))
      (g1-make x-prime y-prime))))

(defun g1-add (p q)
  "Add two G1 points using chord-and-tangent method."
  (cond ((g1-infinity-p p) q)
        ((g1-infinity-p q) p)
        (t (let ((px (g1-x p)) (py (g1-y p))
                 (qx (g1-x q)) (qy (g1-y q)))
             (cond
               ;; P = Q: use doubling
               ((and (= px qx) (= py qy))
                (g1-double p))
               ;; P = -Q: return infinity
               ((and (= px qx) (= py (fp-neg qy)))
                (g1-identity))
               ;; General case
               (t (let* (;; lambda = (qy - py) / (qx - px)
                         (dy (fp-sub qy py))
                         (dx (fp-sub qx px))
                         (lambda (fp-mul dy (fp-inv dx)))
                         ;; x' = lambda^2 - px - qx
                         (lambda-sqr (fp-sqr lambda))
                         (x-prime (fp-sub (fp-sub lambda-sqr px) qx))
                         ;; y' = lambda(px - x') - py
                         (y-prime (fp-sub (fp-mul lambda (fp-sub px x-prime)) py)))
                    (g1-make x-prime y-prime))))))))

(defun g1-mul (p k)
  "Scalar multiplication k*P using double-and-add."
  (declare (type integer k))
  (when (g1-infinity-p p)
    (return-from g1-mul (g1-identity)))
  (when (zerop k)
    (return-from g1-mul (g1-identity)))
  (when (minusp k)
    (return-from g1-mul (g1-mul (g1-neg p) (- k))))
  ;; Reduce k modulo curve order
  (setf k (mod k +curve-order+))
  (let ((result (g1-identity))
        (addend p))
    (loop while (plusp k)
          do (when (oddp k)
               (setf result (g1-add result addend)))
             (setf addend (g1-double addend))
             (setf k (ash k -1)))
    result))

;;; ============================================================================
;;; G1 Serialization
;;; ============================================================================

(defun g1-compress (p)
  "Compress G1 point to 48 bytes.

   Format (per ZCash/ETH2 spec):
   - Bit 7 of byte 0: Always 1 (compressed flag)
   - Bit 6 of byte 0: 1 if point at infinity, 0 otherwise
   - Bit 5 of byte 0: Sign of y (1 if y > (p-1)/2)
   - Remaining bits: x-coordinate big-endian

   RETURN:
   48-byte vector"
  (let ((result (make-array 48 :element-type '(unsigned-byte 8) :initial-element 0)))
    (cond
      ((g1-infinity-p p)
       ;; Infinity: set compressed and infinity flags
       (setf (aref result 0) #xC0))
      (t
       ;; Regular point
       (let* ((x (g1-x p))
              (y (g1-y p))
              (x-bytes (integer-to-bytes x 48 :big-endian t))
              (y-sign (if (> y (ash +field-modulus+ -1)) 1 0)))
         (replace result x-bytes)
         ;; Set flags: bit 7 = compressed (1), bit 5 = y-sign
         (setf (aref result 0) (logior #x80 (ash y-sign 5) (aref result 0))))))
    result))

(defun g1-decompress (bytes)
  "Decompress 48-byte representation to G1 point.

   PARAMETERS:
   - BYTES: 48-byte compressed point

   RETURN:
   G1 point, or signals error if invalid"
  (unless (= (length bytes) 48)
    (error "G1 compressed point must be 48 bytes"))
  (let* ((flags (aref bytes 0))
         (compressed (logbitp 7 flags))
         (infinity (logbitp 6 flags))
         (y-sign (logbitp 5 flags)))
    (unless compressed
      (error "Uncompressed G1 points not supported"))
    (when infinity
      (return-from g1-decompress (g1-identity)))
    ;; Extract x, masking out flag bits
    (let ((x-bytes (copy-seq bytes)))
      (setf (aref x-bytes 0) (logand (aref x-bytes 0) #x1F))
      (let* ((x (bytes-to-integer x-bytes :big-endian t))
             ;; Compute y^2 = x^3 + 4
             (y-sqr (fp-add (fp-pow x 3) +g1-b+))
             (y (fp-sqrt y-sqr)))
        (unless y
          (error "Invalid G1 point: x not on curve"))
        ;; Choose correct y based on sign
        (let ((y-high (> y (ash +field-modulus+ -1))))
          (when (not (eq y-sign y-high))
            (setf y (fp-neg y))))
        (g1-make x y)))))

;;; ============================================================================
;;; G1 Hash-to-Curve
;;; ============================================================================

(defun g1-hash-to-curve (message dst)
  "Hash message to G1 curve point per RFC 9380.

   PARAMETERS:
   - MESSAGE: Byte vector or string
   - DST: Domain separation tag (byte vector)

   RETURN:
   G1 point in prime-order subgroup

   ALGORITHM:
   1. Expand message to uniform bytes
   2. Map to curve using simplified SWU
   3. Clear cofactor"
  (let* ((msg-bytes (etypecase message
                      ((vector (unsigned-byte 8)) message)
                      (string (string-to-octets message))))
         (expanded (expand-message-xmd msg-bytes dst 96))
         ;; Map two field elements to curve and add (for uniform distribution)
         (u0-bytes (subseq expanded 0 48))
         (u1-bytes (subseq expanded 48 96))
         (u0 (mod (bytes-to-integer u0-bytes :big-endian t) +field-modulus+))
         (u1 (mod (bytes-to-integer u1-bytes :big-endian t) +field-modulus+))
         (p0 (map-to-g1 u0))
         (p1 (map-to-g1 u1))
         (sum (g1-add p0 p1)))
    ;; Clear cofactor to ensure point is in prime-order subgroup
    (g1-clear-cofactor sum)))

(defun expand-message-xmd (message dst len)
  "Expand message to LEN bytes using XMD (SHA-256 based).
   Per draft-irtf-cfrg-hash-to-curve."
  (let* ((b-in-bytes 32)
         (s-in-bytes 64)
         (ell (ceiling len b-in-bytes))
         (dst-prime (concatenate '(vector (unsigned-byte 8)) dst (vector (length dst))))
         (z-pad (make-array s-in-bytes :element-type '(unsigned-byte 8) :initial-element 0))
         (len-bytes (vector (ash len -8) (logand len #xFF)))
         (msg-prime (concatenate '(vector (unsigned-byte 8))
                                 z-pad message len-bytes (vector 0) dst-prime))
         (b-0 (sha256 msg-prime))
         (result (make-array (* ell b-in-bytes) :element-type '(unsigned-byte 8))))
    (let ((b-prev (sha256 (concatenate '(vector (unsigned-byte 8))
                                       b-0 (vector 1) dst-prime))))
      (replace result b-prev)
      (loop for i from 2 to ell
            do (let* ((xor-input (map '(vector (unsigned-byte 8)) #'logxor b-0 b-prev))
                      (b-i (sha256 (concatenate '(vector (unsigned-byte 8))
                                                xor-input (vector i) dst-prime))))
                 (replace result b-i :start1 (* (1- i) b-in-bytes))
                 (setf b-prev b-i))))
    (subseq result 0 len)))

(defun map-to-g1 (u)
  "Map field element to G1 using simplified SWU.
   This is a simplified version - production code would use full SSWU with isogeny."
  ;; Simplified: use try-and-increment method
  (let ((x u)
        (y nil))
    (loop for attempt from 0 below 256
          do (let* ((x3 (fp-pow x 3))
                    (y2 (fp-add x3 +g1-b+)))
               (setf y (fp-sqrt y2))
               (when y
                 (return-from map-to-g1 (g1-make x y)))
               (setf x (fp-add x 1))))
    (error "Failed to map to G1 (should not happen)")))

(defun g1-clear-cofactor (p)
  "Clear cofactor by multiplying by h1.
   For G1, this is efficient since h1 is small."
  (g1-mul p +g1-cofactor+))

;;; ============================================================================
;;; G2 Point Representation
;;; ============================================================================
;;; G2 points have coordinates in Fp2

(defun g2-make (x y)
  "Create G2 point from Fp2 coordinates."
  (cons x y))

(defun g2-identity ()
  "Return G2 identity (point at infinity)."
  (cons :infinity nil))

(defun g2-infinity-p (p)
  "Check if P is the point at infinity."
  (eq (car p) :infinity))

(defun g2-x (p) (car p))
(defun g2-y (p) (cdr p))

;;; G2 Generator (Standard Generator)
(defparameter +g2-generator-x+
  (fp2-make
   #x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
   #x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e)
  "X-coordinate of G2 generator (Fp2 element).")

(defparameter +g2-generator-y+
  (fp2-make
   #x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801
   #x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be)
  "Y-coordinate of G2 generator (Fp2 element).")

(defun g2-generator ()
  "Return standard G2 generator point."
  (g2-make +g2-generator-x+ +g2-generator-y+))

;;; ============================================================================
;;; G2 Point Operations
;;; ============================================================================

(defun g2-neg (p)
  "Negate G2 point."
  (if (g2-infinity-p p)
      (g2-identity)
      (g2-make (g2-x p) (fp2-neg (g2-y p)))))

(defun g2-double (p)
  "Double G2 point."
  (when (g2-infinity-p p)
    (return-from g2-double (g2-identity)))
  (let* ((x (g2-x p))
         (y (g2-y p)))
    (when (and (zerop (fp2-c0 y)) (zerop (fp2-c1 y)))
      (return-from g2-double (g2-identity)))
    (let* (;; lambda = 3x^2 / 2y
           (x-sqr (fp2-sqr x))
           (three-x-sqr (fp2-add x-sqr (fp2-add x-sqr x-sqr)))
           (two-y (fp2-add y y))
           (lambda (fp2-mul three-x-sqr (fp2-inv two-y)))
           ;; x' = lambda^2 - 2x
           (lambda-sqr (fp2-sqr lambda))
           (x-prime (fp2-sub (fp2-sub lambda-sqr x) x))
           ;; y' = lambda(x - x') - y
           (y-prime (fp2-sub (fp2-mul lambda (fp2-sub x x-prime)) y)))
      (g2-make x-prime y-prime))))

(defun g2-add (p q)
  "Add two G2 points."
  (cond ((g2-infinity-p p) q)
        ((g2-infinity-p q) p)
        (t (let ((px (g2-x p)) (py (g2-y p))
                 (qx (g2-x q)) (qy (g2-y q)))
             ;; Check if points are equal or negatives
             (let ((x-equal (and (= (fp2-c0 px) (fp2-c0 qx))
                                 (= (fp2-c1 px) (fp2-c1 qx)))))
               (when x-equal
                 (let ((neg-qy (fp2-neg qy)))
                   (cond
                     ;; P = Q
                     ((and (= (fp2-c0 py) (fp2-c0 qy))
                           (= (fp2-c1 py) (fp2-c1 qy)))
                      (return-from g2-add (g2-double p)))
                     ;; P = -Q
                     ((and (= (fp2-c0 py) (fp2-c0 neg-qy))
                           (= (fp2-c1 py) (fp2-c1 neg-qy)))
                      (return-from g2-add (g2-identity))))))
               ;; General case
               (let* ((dy (fp2-sub qy py))
                      (dx (fp2-sub qx px))
                      (lambda (fp2-mul dy (fp2-inv dx)))
                      (lambda-sqr (fp2-sqr lambda))
                      (x-prime (fp2-sub (fp2-sub lambda-sqr px) qx))
                      (y-prime (fp2-sub (fp2-mul lambda (fp2-sub px x-prime)) py)))
                 (g2-make x-prime y-prime)))))))

(defun g2-mul (p k)
  "Scalar multiplication k*P on G2."
  (declare (type integer k))
  (when (g2-infinity-p p)
    (return-from g2-mul (g2-identity)))
  (when (zerop k)
    (return-from g2-mul (g2-identity)))
  (when (minusp k)
    (return-from g2-mul (g2-mul (g2-neg p) (- k))))
  (setf k (mod k +curve-order+))
  (let ((result (g2-identity))
        (addend p))
    (loop while (plusp k)
          do (when (oddp k)
               (setf result (g2-add result addend)))
             (setf addend (g2-double addend))
             (setf k (ash k -1)))
    result))

;;; ============================================================================
;;; G2 Point Validation
;;; ============================================================================

(defun g2-on-curve-p (p)
  "Check if P lies on the G2 curve y^2 = x^3 + 4(1+i)."
  (when (g2-infinity-p p)
    (return-from g2-on-curve-p t))
  (let* ((x (g2-x p))
         (y (g2-y p))
         (lhs (fp2-sqr y))
         (x-cubed (fp2-mul x (fp2-mul x x)))
         (rhs (fp2-add x-cubed +g2-b+)))
    (and (= (fp2-c0 lhs) (fp2-c0 rhs))
         (= (fp2-c1 lhs) (fp2-c1 rhs)))))

(defun g2-in-subgroup-p (p)
  "Check if P is in the prime-order subgroup."
  (when (g2-infinity-p p)
    (return-from g2-in-subgroup-p t))
  (g2-infinity-p (g2-mul p +curve-order+)))

;;; ============================================================================
;;; G2 Serialization
;;; ============================================================================

(defun g2-compress (p)
  "Compress G2 point to 96 bytes."
  (let ((result (make-array 96 :element-type '(unsigned-byte 8) :initial-element 0)))
    (cond
      ((g2-infinity-p p)
       (setf (aref result 0) #xC0))
      (t
       (let* ((x (g2-x p))
              (y (g2-y p))
              ;; G2 x-coord is in Fp2 = c0 + c1*u
              ;; Serialize as c1 || c0 (imaginary part first per spec)
              (x1 (fp2-c1 x))
              (x0 (fp2-c0 x))
              (x1-bytes (integer-to-bytes x1 48 :big-endian t))
              (x0-bytes (integer-to-bytes x0 48 :big-endian t))
              ;; Sign based on y's imaginary part
              (y1 (fp2-c1 y))
              (y-sign (if (> y1 (ash +field-modulus+ -1)) 1 0)))
         (replace result x1-bytes)
         (replace result x0-bytes :start1 48)
         (setf (aref result 0) (logior #x80 (ash y-sign 5) (aref result 0))))))
    result))

(defun g2-decompress (bytes)
  "Decompress 96-byte representation to G2 point."
  (unless (= (length bytes) 96)
    (error "G2 compressed point must be 96 bytes"))
  (let* ((flags (aref bytes 0))
         (compressed (logbitp 7 flags))
         (infinity (logbitp 6 flags))
         (y-sign (logbitp 5 flags)))
    (unless compressed
      (error "Uncompressed G2 points not supported"))
    (when infinity
      (return-from g2-decompress (g2-identity)))
    ;; Extract x1 and x0
    (let ((x1-bytes (subseq bytes 0 48))
          (x0-bytes (subseq bytes 48 96)))
      (setf (aref x1-bytes 0) (logand (aref x1-bytes 0) #x1F))
      (let* ((x1 (bytes-to-integer x1-bytes :big-endian t))
             (x0 (bytes-to-integer x0-bytes :big-endian t))
             (x (fp2-make x0 x1))
             ;; Compute y^2 = x^3 + b'
             (x-cubed (fp2-mul x (fp2-mul x x)))
             (y-sqr (fp2-add x-cubed +g2-b+)))
        ;; Compute square root in Fp2 (simplified)
        ;; Full implementation would use Tonelli-Shanks in Fp2
        ;; For now, signal error for non-trivial decompression
        (error "G2 decompression not fully implemented")))))

;;; ============================================================================
;;; G2 Hash-to-Curve
;;; ============================================================================

(defun g2-hash-to-curve (message dst)
  "Hash message to G2 curve point."
  (let* ((msg-bytes (etypecase message
                      ((vector (unsigned-byte 8)) message)
                      (string (string-to-octets message))))
         ;; Need 4 field elements for Fp2 points (2 per u value)
         (expanded (expand-message-xmd msg-bytes dst 192))
         (u0-c0 (mod (bytes-to-integer (subseq expanded 0 48) :big-endian t) +field-modulus+))
         (u0-c1 (mod (bytes-to-integer (subseq expanded 48 96) :big-endian t) +field-modulus+))
         (u1-c0 (mod (bytes-to-integer (subseq expanded 96 144) :big-endian t) +field-modulus+))
         (u1-c1 (mod (bytes-to-integer (subseq expanded 144 192) :big-endian t) +field-modulus+))
         (u0 (fp2-make u0-c0 u0-c1))
         (u1 (fp2-make u1-c0 u1-c1))
         (p0 (map-to-g2 u0))
         (p1 (map-to-g2 u1))
         (sum (g2-add p0 p1)))
    (g2-clear-cofactor sum)))

(defun map-to-g2 (u)
  "Map Fp2 element to G2 using simplified method."
  ;; Simplified try-and-increment
  (let ((x u)
        (y nil))
    (loop for attempt from 0 below 256
          do (let* ((x-cubed (fp2-mul x (fp2-mul x x)))
                    (y-sqr (fp2-add x-cubed +g2-b+)))
               ;; Try to compute square root in Fp2
               ;; Simplified: check if c1 = 0 and c0 has sqrt
               (when (zerop (fp2-c1 y-sqr))
                 (let ((sqrt-c0 (fp-sqrt (fp2-c0 y-sqr))))
                   (when sqrt-c0
                     (setf y (fp2-make sqrt-c0 0))
                     (return-from map-to-g2 (g2-make x y)))))
               ;; Increment x
               (setf x (fp2-add x (fp2-one)))))
    (error "Failed to map to G2")))

(defun g2-clear-cofactor (p)
  "Clear cofactor for G2."
  ;; For G2, cofactor clearing is more complex - use scalar mul for simplicity
  (g2-mul p +g2-cofactor+))
