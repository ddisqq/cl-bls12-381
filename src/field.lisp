;;;; field.lisp - Field Arithmetic for BLS12-381
;;;;
;;;; Implements arithmetic in Fp, Fp2, and Fp12 tower extensions.

(in-package #:cl-bls12-381)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; BLS12-381 Field Constants
;;; ============================================================================

(defconstant +field-modulus+
  #x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
  "Prime field modulus p for BLS12-381 base field Fp.
   p = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
   381 bits, p = 3 (mod 4), enabling efficient square roots.")

(defconstant +curve-order+
  #x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
  "Order r of the BLS12-381 prime-order subgroups G1, G2, and GT.
   r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
   Approximately 2^255, providing 128-bit security level.")

(defconstant +g1-cofactor+
  #x396c8c005555e1568c00aaab0000aaab
  "Cofactor h1 = (p - 1) / r for G1 subgroup clearing.
   |E(Fp)| = h1 * r")

(defconstant +g2-cofactor+
  #x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5
  "Cofactor h2 for G2 subgroup clearing.
   |E'(Fp2)| = h2 * r")

;; Non-residue u where Fp2 = Fp[x]/(x^2 - u)
;; For BLS12-381, u = -1, so Fp2 elements are a + bi with i^2 = -1
(defconstant +fp2-nonresidue+ (- +field-modulus+ 1)
  "Non-residue u = -1 for Fp2 tower construction.")

;;; ============================================================================
;;; Fp (Base Field) Arithmetic
;;; ============================================================================

(declaim (inline fp-reduce fp-add fp-sub fp-neg fp-mul fp-sqr))

(defun fp-reduce (x)
  "Reduce integer X to canonical representative in [0, p)."
  (declare (type integer x))
  (mod x +field-modulus+))

(defun fp-add (a b)
  "Compute (A + B) mod p in Fp."
  (declare (type integer a b))
  (let ((sum (+ a b)))
    (if (>= sum +field-modulus+)
        (- sum +field-modulus+)
        sum)))

(defun fp-sub (a b)
  "Compute (A - B) mod p in Fp."
  (declare (type integer a b))
  (if (< a b)
      (+ (- a b) +field-modulus+)
      (- a b)))

(defun fp-neg (a)
  "Compute -A mod p in Fp."
  (declare (type integer a))
  (if (zerop a)
      0
      (- +field-modulus+ a)))

(defun fp-mul (a b)
  "Compute (A * B) mod p in Fp."
  (declare (type integer a b))
  (mod (* a b) +field-modulus+))

(defun fp-sqr (a)
  "Compute A^2 mod p in Fp."
  (declare (type integer a))
  (mod (* a a) +field-modulus+))

(defun fp-inv (a)
  "Compute A^(-1) mod p using Fermat's little theorem.
   Returns A^(p-2) mod p."
  (declare (type integer a))
  (when (zerop a)
    (error "Cannot invert zero in Fp"))
  (mod-expt a (- +field-modulus+ 2) +field-modulus+))

(defun fp-pow (a n)
  "Compute A^N mod p using binary exponentiation."
  (declare (type integer a n))
  (mod-expt a (mod n (1- +field-modulus+)) +field-modulus+))

(defun fp-legendre (a)
  "Compute Legendre symbol (a/p).
   Returns 1 if a is quadratic residue, -1 if non-residue, 0 if a = 0."
  (declare (type integer a))
  (cond ((zerop a) 0)
        (t (let ((result (mod-expt a (ash (1- +field-modulus+) -1) +field-modulus+)))
             (if (= result 1) 1 -1)))))

(defun fp-sqrt (a)
  "Compute square root in Fp if it exists.
   For BLS12-381, p = 3 (mod 4), so sqrt(a) = a^((p+1)/4) when a is QR.

   RETURN:
   Square root if exists, NIL if a is not a quadratic residue."
  (declare (type integer a))
  (when (zerop a)
    (return-from fp-sqrt 0))
  ;; Check if a is a quadratic residue
  (unless (= (fp-legendre a) 1)
    (return-from fp-sqrt nil))
  ;; p = 3 (mod 4), so sqrt(a) = a^((p+1)/4)
  (let* ((exp (ash (1+ +field-modulus+) -2))
         (root (mod-expt a exp +field-modulus+)))
    ;; Verify (expensive but safe)
    (if (= (fp-sqr root) (fp-reduce a))
        root
        nil)))

;;; ============================================================================
;;; Fp2 (Quadratic Extension) Arithmetic
;;; ============================================================================
;;; Fp2 = Fp[u]/(u^2 + 1), elements are (a + bu) represented as (a . b)

(defun fp2-make (a b)
  "Create Fp2 element a + bu."
  (cons (fp-reduce a) (fp-reduce b)))

(defun fp2-zero ()
  "Return Fp2 zero element."
  (cons 0 0))

(defun fp2-one ()
  "Return Fp2 multiplicative identity."
  (cons 1 0))

(defun fp2-c0 (x) (car x))
(defun fp2-c1 (x) (cdr x))

(defun fp2-add (a b)
  "Add two Fp2 elements."
  (cons (fp-add (fp2-c0 a) (fp2-c0 b))
        (fp-add (fp2-c1 a) (fp2-c1 b))))

(defun fp2-sub (a b)
  "Subtract Fp2 elements."
  (cons (fp-sub (fp2-c0 a) (fp2-c0 b))
        (fp-sub (fp2-c1 a) (fp2-c1 b))))

(defun fp2-neg (a)
  "Negate Fp2 element."
  (cons (fp-neg (fp2-c0 a))
        (fp-neg (fp2-c1 a))))

(defun fp2-mul (a b)
  "Multiply Fp2 elements using Karatsuba-like formula.
   (a0 + a1*u)(b0 + b1*u) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*u
   Since u^2 = -1."
  (let* ((a0 (fp2-c0 a)) (a1 (fp2-c1 a))
         (b0 (fp2-c0 b)) (b1 (fp2-c1 b))
         (t0 (fp-mul a0 b0))
         (t1 (fp-mul a1 b1))
         ;; c0 = a0*b0 - a1*b1
         (c0 (fp-sub t0 t1))
         ;; c1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 = a0*b1 + a1*b0
         (c1 (fp-sub (fp-sub (fp-mul (fp-add a0 a1) (fp-add b0 b1)) t0) t1)))
    (cons c0 c1)))

(defun fp2-sqr (a)
  "Square Fp2 element.
   (a + bu)^2 = (a^2 - b^2) + 2ab*u"
  (let* ((a0 (fp2-c0 a)) (a1 (fp2-c1 a))
         ;; c0 = (a0 + a1)(a0 - a1) = a0^2 - a1^2
         (c0 (fp-mul (fp-add a0 a1) (fp-sub a0 a1)))
         ;; c1 = 2 * a0 * a1
         (c1 (fp-mul 2 (fp-mul a0 a1))))
    (cons c0 (fp-reduce c1))))

(defun fp2-inv (a)
  "Invert Fp2 element.
   (a + bu)^(-1) = (a - bu)/(a^2 + b^2)"
  (let* ((a0 (fp2-c0 a)) (a1 (fp2-c1 a))
         ;; norm = a^2 + b^2 (since u^2 = -1, norm = a*conj(a))
         (norm (fp-add (fp-sqr a0) (fp-sqr a1)))
         (norm-inv (fp-inv norm)))
    (cons (fp-mul a0 norm-inv)
          (fp-neg (fp-mul a1 norm-inv)))))

(defun fp2-conjugate (a)
  "Conjugate of Fp2 element: (a + bu) -> (a - bu)."
  (cons (fp2-c0 a)
        (fp-neg (fp2-c1 a))))

(defun fp2-frobenius (a)
  "Apply Frobenius endomorphism: x -> x^p.
   For Fp2, this is conjugation since (a + bu)^p = a - bu."
  (fp2-conjugate a))

(defun fp2-mul-by-nonresidue (a)
  "Multiply Fp2 element by non-residue for Fp6 tower.
   The non-residue is (1 + u), so (a + bu)(1 + u) = (a - b) + (a + b)u."
  (let ((a0 (fp2-c0 a)) (a1 (fp2-c1 a)))
    (cons (fp-sub a0 a1)
          (fp-add a0 a1))))

;;; ============================================================================
;;; Fp6 Arithmetic (for Fp12 tower construction)
;;; ============================================================================
;;; Fp6 = Fp2[v]/(v^3 - (1+u)), elements are (c0 + c1*v + c2*v^2)

(defun fp6-make (c0 c1 c2)
  "Create Fp6 element from three Fp2 coefficients."
  (vector c0 c1 c2))

(defun fp6-zero ()
  (fp6-make (fp2-zero) (fp2-zero) (fp2-zero)))

(defun fp6-one ()
  (fp6-make (fp2-one) (fp2-zero) (fp2-zero)))

(defun fp6-c0 (x) (aref x 0))
(defun fp6-c1 (x) (aref x 1))
(defun fp6-c2 (x) (aref x 2))

(defun fp6-add (a b)
  (fp6-make (fp2-add (fp6-c0 a) (fp6-c0 b))
            (fp2-add (fp6-c1 a) (fp6-c1 b))
            (fp2-add (fp6-c2 a) (fp6-c2 b))))

(defun fp6-sub (a b)
  (fp6-make (fp2-sub (fp6-c0 a) (fp6-c0 b))
            (fp2-sub (fp6-c1 a) (fp6-c1 b))
            (fp2-sub (fp6-c2 a) (fp6-c2 b))))

(defun fp6-neg (a)
  (fp6-make (fp2-neg (fp6-c0 a))
            (fp2-neg (fp6-c1 a))
            (fp2-neg (fp6-c2 a))))

(defun fp6-mul (a b)
  "Multiply Fp6 elements using schoolbook with reduction."
  (let* ((a0 (fp6-c0 a)) (a1 (fp6-c1 a)) (a2 (fp6-c2 a))
         (b0 (fp6-c0 b)) (b1 (fp6-c1 b)) (b2 (fp6-c2 b))
         ;; Products
         (t0 (fp2-mul a0 b0))
         (t1 (fp2-mul a1 b1))
         (t2 (fp2-mul a2 b2))
         ;; c0 = a0*b0 + (a1*b2 + a2*b1) * nonresidue
         (c0 (fp2-add t0 (fp2-mul-by-nonresidue
                          (fp2-add (fp2-mul a1 b2) (fp2-mul a2 b1)))))
         ;; c1 = (a0*b1 + a1*b0) + a2*b2 * nonresidue
         (c1 (fp2-add (fp2-add (fp2-mul a0 b1) (fp2-mul a1 b0))
                      (fp2-mul-by-nonresidue t2)))
         ;; c2 = a0*b2 + a1*b1 + a2*b0
         (c2 (fp2-add (fp2-add (fp2-mul a0 b2) t1) (fp2-mul a2 b0))))
    (fp6-make c0 c1 c2)))

(defun fp6-sqr (a)
  "Square Fp6 element."
  (fp6-mul a a))

(defun fp6-inv (a)
  "Invert Fp6 element."
  (let* ((c0 (fp6-c0 a)) (c1 (fp6-c1 a)) (c2 (fp6-c2 a))
         (t0 (fp2-sub (fp2-sqr c0) (fp2-mul-by-nonresidue (fp2-mul c1 c2))))
         (t1 (fp2-sub (fp2-mul-by-nonresidue (fp2-sqr c2)) (fp2-mul c0 c1)))
         (t2 (fp2-sub (fp2-sqr c1) (fp2-mul c0 c2)))
         (t3 (fp2-mul c0 t0))
         (t3 (fp2-add t3 (fp2-mul-by-nonresidue (fp2-add (fp2-mul c2 t1) (fp2-mul c1 t2)))))
         (t3-inv (fp2-inv t3)))
    (fp6-make (fp2-mul t0 t3-inv)
              (fp2-mul t1 t3-inv)
              (fp2-mul t2 t3-inv))))

;;; ============================================================================
;;; Fp12 Arithmetic
;;; ============================================================================
;;; Fp12 = Fp6[w]/(w^2 - v), elements are (c0 + c1*w)

(defun fp12-make (c0 c1)
  "Create Fp12 element from two Fp6 coefficients."
  (cons c0 c1))

(defun fp12-zero ()
  (fp12-make (fp6-zero) (fp6-zero)))

(defun fp12-one ()
  (fp12-make (fp6-one) (fp6-zero)))

(defun fp12-c0 (x) (car x))
(defun fp12-c1 (x) (cdr x))

(defun fp12-add (a b)
  (fp12-make (fp6-add (fp12-c0 a) (fp12-c0 b))
             (fp6-add (fp12-c1 a) (fp12-c1 b))))

(defun fp12-sub (a b)
  (fp12-make (fp6-sub (fp12-c0 a) (fp12-c0 b))
             (fp6-sub (fp12-c1 a) (fp12-c1 b))))

(defun fp12-neg (a)
  (fp12-make (fp6-neg (fp12-c0 a))
             (fp6-neg (fp12-c1 a))))

(defun fp6-mul-by-v (a)
  "Multiply Fp6 by v (shifts coefficients and multiplies by nonresidue)."
  (fp6-make (fp2-mul-by-nonresidue (fp6-c2 a))
            (fp6-c0 a)
            (fp6-c1 a)))

(defun fp12-mul (a b)
  "Multiply Fp12 elements.
   (a0 + a1*w)(b0 + b1*w) = (a0*b0 + a1*b1*v) + (a0*b1 + a1*b0)*w"
  (let* ((a0 (fp12-c0 a)) (a1 (fp12-c1 a))
         (b0 (fp12-c0 b)) (b1 (fp12-c1 b))
         (t0 (fp6-mul a0 b0))
         (t1 (fp6-mul a1 b1))
         ;; c0 = a0*b0 + a1*b1*v
         (c0 (fp6-add t0 (fp6-mul-by-v t1)))
         ;; c1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1
         (c1 (fp6-sub (fp6-sub (fp6-mul (fp6-add a0 a1) (fp6-add b0 b1)) t0) t1)))
    (fp12-make c0 c1)))

(defun fp12-sqr (a)
  "Square Fp12 element."
  (fp12-mul a a))

(defun fp12-inv (a)
  "Invert Fp12 element."
  (let* ((c0 (fp12-c0 a)) (c1 (fp12-c1 a))
         ;; t = c0^2 - c1^2 * v
         (t0 (fp6-sub (fp6-sqr c0) (fp6-mul-by-v (fp6-sqr c1))))
         (t-inv (fp6-inv t0)))
    (fp12-make (fp6-mul c0 t-inv)
               (fp6-neg (fp6-mul c1 t-inv)))))

(defun fp12-conjugate (a)
  "Conjugate of Fp12: (c0 + c1*w) -> (c0 - c1*w)."
  (fp12-make (fp12-c0 a)
             (fp6-neg (fp12-c1 a))))

(defun fp12-frobenius (a)
  "Apply Frobenius endomorphism x -> x^p to Fp12."
  ;; Simplified - full implementation would apply Frobenius coefficients
  (fp12-conjugate a))

(defun fp12-pow (a n)
  "Compute A^N in Fp12 using binary exponentiation."
  (declare (type integer n))
  (cond ((zerop n) (fp12-one))
        ((= n 1) a)
        (t (let ((result (fp12-one))
                 (base a))
             (loop while (plusp n)
                   do (when (oddp n)
                        (setf result (fp12-mul result base)))
                      (setf n (ash n -1))
                      (setf base (fp12-sqr base)))
             result))))
