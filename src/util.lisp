;;;; util.lisp - Utility functions for cl-bls12-381
;;;;
;;;; Byte manipulation, randomness, and cryptographic primitives.

(in-package #:cl-bls12-381)

;;; ============================================================================
;;; Byte/Integer Conversion
;;; ============================================================================

(defun bytes-to-integer (bytes &key (big-endian t))
  "Convert byte vector to integer.

   PARAMETERS:
   - BYTES: Vector of (unsigned-byte 8)
   - BIG-ENDIAN: If T (default), MSB first; if NIL, LSB first

   RETURN:
   Non-negative integer"
  (declare (type (vector (unsigned-byte 8)) bytes))
  (let ((result 0)
        (len (length bytes)))
    (if big-endian
        (loop for i from 0 below len
              do (setf result (logior (ash result 8) (aref bytes i))))
        (loop for i from (1- len) downto 0
              do (setf result (logior (ash result 8) (aref bytes i)))))
    result))

(defun integer-to-bytes (n size &key (big-endian t))
  "Convert integer to byte vector of specified size.

   PARAMETERS:
   - N: Non-negative integer
   - SIZE: Output size in bytes
   - BIG-ENDIAN: If T (default), MSB first

   RETURN:
   Vector of (unsigned-byte 8) of length SIZE"
  (declare (type integer n) (type (integer 1) size))
  (let ((result (make-array size :element-type '(unsigned-byte 8) :initial-element 0)))
    (if big-endian
        (loop for i from (1- size) downto 0
              for j from 0
              while (plusp n)
              do (setf (aref result i) (logand n #xFF))
                 (setf n (ash n -8)))
        (loop for i from 0 below size
              while (plusp n)
              do (setf (aref result i) (logand n #xFF))
                 (setf n (ash n -8))))
    result))

;;; ============================================================================
;;; Constant-Time Comparison
;;; ============================================================================

(defun constant-time-bytes= (a b)
  "Compare two byte vectors in constant time.

   SECURITY:
   Prevents timing attacks by always comparing all bytes regardless
   of where differences occur.

   RETURN:
   T if equal, NIL if different or different lengths"
  (declare (type (vector (unsigned-byte 8)) a b))
  (let ((len-a (length a))
        (len-b (length b)))
    (unless (= len-a len-b)
      (return-from constant-time-bytes= nil))
    (let ((diff 0))
      (declare (type (unsigned-byte 8) diff))
      (dotimes (i len-a)
        (setf diff (logior diff (logxor (aref a i) (aref b i)))))
      (zerop diff))))

;;; ============================================================================
;;; Random Number Generation
;;; ============================================================================

(defun get-random-bytes (n)
  "Generate N cryptographically secure random bytes.

   Uses SBCL's random state seeded from system entropy."
  (declare (type (integer 1) n))
  (let ((result (make-array n :element-type '(unsigned-byte 8))))
    #+sbcl
    (let ((state (sb-ext:seed-random-state t)))
      (dotimes (i n)
        (setf (aref result i) (random 256 state))))
    #-sbcl
    (dotimes (i n)
      (setf (aref result i) (random 256)))
    result))

;;; ============================================================================
;;; SHA-256 Implementation
;;; ============================================================================

(defconstant +sha256-k+
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
  "SHA-256 round constants.")

(defconstant +sha256-h0+
  #(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)
  "SHA-256 initial hash values.")

(declaim (inline sha256-rotr sha256-ch sha256-maj sha256-sigma0 sha256-sigma1
                 sha256-Sigma0 sha256-Sigma1))

(defun sha256-rotr (x n)
  (declare (type (unsigned-byte 32) x) (type (integer 0 31) n))
  (logior (ash x (- n)) (logand #xFFFFFFFF (ash x (- 32 n)))))

(defun sha256-ch (x y z)
  (declare (type (unsigned-byte 32) x y z))
  (logxor (logand x y) (logand (lognot x) z)))

(defun sha256-maj (x y z)
  (declare (type (unsigned-byte 32) x y z))
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sha256-Sigma0 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 2) (sha256-rotr x 13) (sha256-rotr x 22)))

(defun sha256-Sigma1 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 6) (sha256-rotr x 11) (sha256-rotr x 25)))

(defun sha256-sigma0 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 7) (sha256-rotr x 18) (ash x -3)))

(defun sha256-sigma1 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 17) (sha256-rotr x 19) (ash x -10)))

(defun sha256-pad-message (message)
  "Pad message according to SHA-256 specification."
  (let* ((len (length message))
         (bit-len (* len 8))
         (pad-len (- 64 (mod (+ len 9) 64)))
         (total-len (+ len 1 pad-len 8))
         (padded (make-array total-len :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace padded message)
    (setf (aref padded len) #x80)
    ;; Append length as 64-bit big-endian
    (loop for i from 0 below 8
          do (setf (aref padded (+ len 1 pad-len i))
                   (logand #xFF (ash bit-len (- (* 8 (- 7 i)))))))
    padded))

(defun sha256-process-block (block h)
  "Process a 64-byte block."
  (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
    ;; Prepare message schedule
    (dotimes (i 16)
      (setf (aref w i)
            (logior (ash (aref block (* i 4)) 24)
                    (ash (aref block (+ (* i 4) 1)) 16)
                    (ash (aref block (+ (* i 4) 2)) 8)
                    (aref block (+ (* i 4) 3)))))
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (logand #xFFFFFFFF
                           (+ (sha256-sigma1 (aref w (- i 2)))
                              (aref w (- i 7))
                              (sha256-sigma0 (aref w (- i 15)))
                              (aref w (- i 16))))))
    ;; Initialize working variables
    (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
          (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
      (declare (type (unsigned-byte 32) a b c d e f g hh))
      ;; 64 rounds
      (dotimes (i 64)
        (let* ((t1 (logand #xFFFFFFFF
                           (+ hh (sha256-Sigma1 e) (sha256-ch e f g)
                              (aref +sha256-k+ i) (aref w i))))
               (t2 (logand #xFFFFFFFF
                           (+ (sha256-Sigma0 a) (sha256-maj a b c)))))
          (setf hh g g f f e (logand #xFFFFFFFF (+ d t1))
                d c c b b a a (logand #xFFFFFFFF (+ t1 t2)))))
      ;; Add to hash
      (setf (aref h 0) (logand #xFFFFFFFF (+ (aref h 0) a))
            (aref h 1) (logand #xFFFFFFFF (+ (aref h 1) b))
            (aref h 2) (logand #xFFFFFFFF (+ (aref h 2) c))
            (aref h 3) (logand #xFFFFFFFF (+ (aref h 3) d))
            (aref h 4) (logand #xFFFFFFFF (+ (aref h 4) e))
            (aref h 5) (logand #xFFFFFFFF (+ (aref h 5) f))
            (aref h 6) (logand #xFFFFFFFF (+ (aref h 6) g))
            (aref h 7) (logand #xFFFFFFFF (+ (aref h 7) hh))))))

(defun sha256 (message)
  "Compute SHA-256 hash of message.

   PARAMETERS:
   - MESSAGE: Vector of (unsigned-byte 8) or string

   RETURN:
   32-byte hash as (vector (unsigned-byte 8))"
  (let* ((msg (etypecase message
                ((vector (unsigned-byte 8)) message)
                (string (map '(vector (unsigned-byte 8)) #'char-code message))))
         (padded (sha256-pad-message msg))
         (h (copy-seq +sha256-h0+)))
    ;; Process each 64-byte block
    (loop for i from 0 below (length padded) by 64
          do (sha256-process-block (subseq padded i (+ i 64)) h))
    ;; Convert to bytes
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 8)
        (let ((word (aref h i)))
          (setf (aref result (* i 4)) (logand #xFF (ash word -24))
                (aref result (+ (* i 4) 1)) (logand #xFF (ash word -16))
                (aref result (+ (* i 4) 2)) (logand #xFF (ash word -8))
                (aref result (+ (* i 4) 3)) (logand #xFF word))))
      result)))

;;; ============================================================================
;;; HMAC-SHA256
;;; ============================================================================

(defun hmac-sha256 (key message)
  "Compute HMAC-SHA256(key, message).

   PARAMETERS:
   - KEY: Secret key bytes
   - MESSAGE: Message bytes

   RETURN:
   32-byte MAC"
  (let* ((key-bytes (etypecase key
                      ((vector (unsigned-byte 8)) key)
                      (string (map '(vector (unsigned-byte 8)) #'char-code key))))
         (msg-bytes (etypecase message
                      ((vector (unsigned-byte 8)) message)
                      (string (map '(vector (unsigned-byte 8)) #'char-code message))))
         ;; If key > 64 bytes, hash it
         (k (if (> (length key-bytes) 64)
                (sha256 key-bytes)
                key-bytes))
         ;; Pad key to 64 bytes
         (k-padded (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace k-padded k)
    ;; Compute inner and outer padding
    (let ((ipad (make-array 64 :element-type '(unsigned-byte 8)))
          (opad (make-array 64 :element-type '(unsigned-byte 8))))
      (dotimes (i 64)
        (setf (aref ipad i) (logxor (aref k-padded i) #x36))
        (setf (aref opad i) (logxor (aref k-padded i) #x5c)))
      ;; H(opad || H(ipad || message))
      (sha256 (concatenate '(vector (unsigned-byte 8))
                           opad
                           (sha256 (concatenate '(vector (unsigned-byte 8))
                                                ipad msg-bytes)))))))

;;; ============================================================================
;;; Modular Arithmetic Helpers
;;; ============================================================================

(defun mod-expt (base exp mod)
  "Compute BASE^EXP mod MOD using binary exponentiation."
  (declare (type integer base exp mod))
  (let ((result 1)
        (b (mod base mod)))
    (loop while (plusp exp)
          do (when (oddp exp)
               (setf result (mod (* result b) mod)))
             (setf exp (ash exp -1))
             (setf b (mod (* b b) mod)))
    result))

;;; ============================================================================
;;; String/Bytes Conversion
;;; ============================================================================

(defun string-to-octets (string &key (encoding :utf-8))
  "Convert string to byte vector.
   Currently only supports ASCII/UTF-8 for ASCII range."
  (declare (ignore encoding))
  (map '(vector (unsigned-byte 8)) #'char-code string))

(defun octets-to-string (octets &key (encoding :utf-8))
  "Convert byte vector to string.
   Currently only supports ASCII/UTF-8 for ASCII range."
  (declare (ignore encoding))
  (map 'string #'code-char octets))
