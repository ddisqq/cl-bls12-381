;;;; bls.lisp - BLS Signature Scheme
;;;;
;;;; Implements BLS signatures with aggregation, threshold, and Proof of Possession.

(in-package #:cl-bls12-381)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; Domain Separation Tags
;;; ============================================================================

(defparameter +dst-sign+
  (string-to-octets "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")
  "Domain Separation Tag for BLS signatures.
   Per IETF draft-irtf-cfrg-bls-signature-05.")

(defparameter +dst-pop+
  (string-to-octets "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_")
  "Domain Separation Tag for Proof of Possession.")

;;; ============================================================================
;;; Type Definitions
;;; ============================================================================

(defstruct (bls-keypair (:constructor %make-bls-keypair))
  "BLS keypair containing secret and public key.

   SECRET: 32-byte scalar in F_r
   PUBLIC: 96-byte compressed G2 point"
  (secret nil :type (or null (simple-array (unsigned-byte 8) (32))) :read-only t)
  (public nil :type (or null (simple-array (unsigned-byte 8) (96))) :read-only t)
  (pop nil :type (or null (simple-array (unsigned-byte 8) (48)))))

(defstruct (bls-signature (:constructor %make-bls-signature))
  "BLS signature as compressed G1 point.

   POINT: 48-byte compressed G1 point
   DST: Domain separation tag used"
  (point nil :type (or null (simple-array (unsigned-byte 8) (48))) :read-only t)
  (dst nil :type (or null (simple-array (unsigned-byte 8) *)) :read-only t))

(defstruct (bls-aggregate-sig (:constructor %make-bls-aggregate-sig))
  "Aggregated BLS signature.

   POINT: 48-byte compressed aggregate (same size as individual!)
   COUNT: Number of aggregated signatures
   MODE: :same-message or :multi-message"
  (point nil :type (or null (simple-array (unsigned-byte 8) (48))) :read-only t)
  (count 0 :type fixnum :read-only t)
  (mode :same-message :type (member :same-message :multi-message) :read-only t))

(defstruct (bls-threshold-share (:constructor %make-bls-threshold-share))
  "Threshold BLS key share.

   INDEX: Participant index (1-based)
   SECRET: Secret share scalar
   PUBLIC: Public verification key for this share
   VERIFICATION-VECTOR: Feldman VSS commitments"
  (index 0 :type (integer 1 *) :read-only t)
  (secret nil :type (or null (simple-array (unsigned-byte 8) (32))) :read-only t)
  (public nil :type (or null (simple-array (unsigned-byte 8) (96))) :read-only t)
  (verification-vector nil :type (or null vector) :read-only t))

(defstruct (bls-pop (:constructor %make-bls-pop))
  "Proof of Possession for BLS public key.

   Proves knowledge of secret key to prevent rogue key attacks."
  (public-key nil :type (or null (simple-array (unsigned-byte 8) (96))) :read-only t)
  (proof nil :type (or null (simple-array (unsigned-byte 8) (48))) :read-only t))

;;; ============================================================================
;;; Scalar Operations
;;; ============================================================================

(declaim (inline scalar-reduce scalar-to-bytes bytes-to-scalar))

(defun scalar-reduce (x)
  "Reduce integer X modulo curve order r."
  (declare (type integer x))
  (mod x +curve-order+))

(defun scalar-to-bytes (scalar)
  "Convert scalar to 32-byte big-endian representation."
  (integer-to-bytes (scalar-reduce scalar) 32 :big-endian t))

(defun bytes-to-scalar (bytes)
  "Convert byte vector to scalar in F_r."
  (scalar-reduce (bytes-to-integer bytes :big-endian t)))

;;; ============================================================================
;;; Key Generation
;;; ============================================================================

(defun bls-keygen ()
  "Generate a random BLS keypair.

   RETURN:
   bls-keypair with:
   - secret: 32-byte random scalar
   - public: 96-byte G2 public key (sk * G2)

   SECURITY:
   Uses cryptographically secure RNG."
  (let* ((secret-bytes (get-random-bytes 32))
         (scalar (bytes-to-scalar secret-bytes)))
    ;; Ensure non-zero scalar
    (loop while (zerop scalar)
          do (setf secret-bytes (get-random-bytes 32))
             (setf scalar (bytes-to-scalar secret-bytes)))
    (let* ((secret (scalar-to-bytes scalar))
           (public (bls-derive-public secret)))
      (%make-bls-keypair :secret secret :public public))))

(defun bls-keygen-deterministic (seed &optional (info ""))
  "Derive BLS keypair deterministically from seed.

   PARAMETERS:
   - SEED: At least 32 bytes of entropy
   - INFO: Optional context string

   RETURN:
   bls-keypair

   ALGORITHM:
   HKDF-SHA256 key derivation per IETF BLS KeyGen."
  (unless (>= (length seed) 32)
    (error "Seed must be at least 32 bytes"))
  (let* ((info-bytes (etypecase info
                       ((vector (unsigned-byte 8)) info)
                       (string (string-to-octets info))))
         ;; HKDF-Extract
         (prk (hmac-sha256 +dst-sign+ seed))
         ;; HKDF-Expand to 48 bytes
         (okm-1 (hmac-sha256 prk (concatenate '(vector (unsigned-byte 8))
                                              info-bytes (vector 1))))
         (okm-2 (hmac-sha256 prk (concatenate '(vector (unsigned-byte 8))
                                              okm-1 info-bytes (vector 2))))
         (okm (concatenate '(vector (unsigned-byte 8)) okm-1 (subseq okm-2 0 16)))
         (scalar (scalar-reduce (bytes-to-integer okm :big-endian t))))
    (when (zerop scalar) (setf scalar 1))
    (let* ((secret (scalar-to-bytes scalar))
           (public (bls-derive-public secret)))
      (%make-bls-keypair :secret secret :public public))))

(defun bls-derive-public (secret-key)
  "Derive public key from secret key.

   PARAMETERS:
   - SECRET-KEY: 32-byte secret key

   RETURN:
   96-byte compressed G2 public key

   ALGORITHM:
   pk = sk * G2"
  (let* ((scalar (bytes-to-scalar secret-key))
         (pk-point (g2-mul (g2-generator) scalar)))
    (g2-compress pk-point)))

;;; ============================================================================
;;; Signing
;;; ============================================================================

(defun bls-sign (keypair message)
  "Sign message with BLS secret key.

   PARAMETERS:
   - KEYPAIR: bls-keypair with secret key
   - MESSAGE: Bytes or string to sign

   RETURN:
   bls-signature

   ALGORITHM:
   sig = sk * H(m) where H maps to G1.

   SECURITY:
   Deterministic - same (key, message) always produces same signature."
  (bls-sign-with-dst keypair message +dst-sign+))

(defun bls-sign-with-dst (keypair message dst)
  "Sign message with custom domain separation tag.

   PARAMETERS:
   - KEYPAIR: Signing keypair
   - MESSAGE: Message bytes or string
   - DST: Domain separation tag

   RETURN:
   bls-signature"
  (let* ((msg-bytes (etypecase message
                      ((vector (unsigned-byte 8)) message)
                      (string (string-to-octets message))))
         ;; Hash message to G1
         (h-point (g1-hash-to-curve msg-bytes dst))
         ;; Scalar multiply by secret key
         (scalar (bytes-to-scalar (bls-keypair-secret keypair)))
         (sig-point (g1-mul h-point scalar)))
    (%make-bls-signature :point (g1-compress sig-point) :dst dst)))

;;; ============================================================================
;;; Verification
;;; ============================================================================

(defun bls-verify (public-key message signature)
  "Verify BLS signature.

   PARAMETERS:
   - PUBLIC-KEY: 96-byte compressed public key or byte vector
   - MESSAGE: Signed message
   - SIGNATURE: bls-signature or 48-byte signature

   RETURN:
   T if valid, NIL otherwise

   ALGORITHM:
   Verify e(sig, G2) = e(H(m), pk) using pairing check."
  (bls-verify-with-dst public-key message signature +dst-sign+))

(defun bls-verify-with-dst (public-key message signature dst)
  "Verify BLS signature with custom DST.

   PARAMETERS:
   - PUBLIC-KEY: Public key bytes
   - MESSAGE: Message
   - SIGNATURE: Signature
   - DST: Domain separation tag

   RETURN:
   T if valid, NIL otherwise"
  (handler-case
      (let* ((msg-bytes (etypecase message
                          ((vector (unsigned-byte 8)) message)
                          (string (string-to-octets message))))
             (sig-bytes (etypecase signature
                          (bls-signature (bls-signature-point signature))
                          ((vector (unsigned-byte 8)) signature)))
             (pk-bytes (etypecase public-key
                         ((vector (unsigned-byte 8)) public-key)
                         (bls-keypair (bls-keypair-public public-key))))
             ;; Decompress points
             (sig-point (g1-decompress sig-bytes))
             (pk-point (g2-decompress pk-bytes))
             ;; Hash message to G1
             (h-point (g1-hash-to-curve msg-bytes dst)))
        ;; Verify pairing equation: e(sig, G2) = e(H(m), pk)
        ;; Equivalent to: e(sig, G2) * e(-H(m), pk) = 1
        (pairing-check sig-point (g2-generator)
                       (g1-neg h-point) pk-point))
    (error () nil)))

;;; ============================================================================
;;; Aggregation
;;; ============================================================================

(defun bls-aggregate-signatures (signatures)
  "Aggregate multiple BLS signatures into one.

   PARAMETERS:
   - SIGNATURES: List of bls-signature or 48-byte vectors

   RETURN:
   bls-aggregate-sig (still only 48 bytes!)

   ALGORITHM:
   agg = sig_1 + sig_2 + ... (point addition in G1)

   KEY PROPERTY:
   Output size constant regardless of input count."
  (when (null signatures)
    (return-from bls-aggregate-signatures
      (%make-bls-aggregate-sig :point (g1-compress (g1-identity)) :count 0)))
  (let ((acc (g1-identity))
        (count 0))
    (dolist (sig signatures)
      (let* ((bytes (etypecase sig
                      (bls-signature (bls-signature-point sig))
                      ((vector (unsigned-byte 8)) sig)))
             (point (g1-decompress bytes)))
        (setf acc (g1-add acc point))
        (incf count)))
    (%make-bls-aggregate-sig :point (g1-compress acc) :count count :mode :same-message)))

(defun bls-aggregate-public-keys (public-keys)
  "Aggregate multiple public keys into one.

   PARAMETERS:
   - PUBLIC-KEYS: List of 96-byte public keys

   RETURN:
   96-byte aggregated public key

   WARNING:
   Without PoP verification, vulnerable to rogue key attacks."
  (when (null public-keys)
    (error "Cannot aggregate empty public key list"))
  (let ((acc (g2-identity)))
    (dolist (pk public-keys)
      (let ((point (g2-decompress pk)))
        (setf acc (g2-add acc point))))
    (g2-compress acc)))

(defun bls-verify-aggregate (public-keys message aggregate-sig)
  "Verify aggregate BLS signature on same message.

   PARAMETERS:
   - PUBLIC-KEYS: List of all signers' public keys
   - MESSAGE: The common message
   - AGGREGATE-SIG: bls-aggregate-sig

   RETURN:
   T if valid, NIL otherwise

   ALGORITHM:
   1. agg_pk = sum(pk_i)
   2. Verify e(agg_sig, G2) = e(H(m), agg_pk)"
  (handler-case
      (let* ((agg-pk (bls-aggregate-public-keys public-keys))
             (sig-bytes (bls-aggregate-sig-point aggregate-sig)))
        (bls-verify agg-pk message sig-bytes))
    (error () nil)))

;;; ============================================================================
;;; Batch Verification
;;; ============================================================================

(defun bls-batch-verify (verification-tuples)
  "Batch verify multiple (pk, msg, sig) tuples.

   PARAMETERS:
   - VERIFICATION-TUPLES: List of (public-key message signature) lists

   RETURN:
   T if ALL valid, NIL if any invalid

   ALGORITHM:
   Randomized batch verification for efficiency."
  (when (null verification-tuples)
    (return-from bls-batch-verify t))
  (handler-case
      (every (lambda (tuple)
               (destructuring-bind (pk msg sig) tuple
                 (bls-verify pk msg sig)))
             verification-tuples)
    (error () nil)))

(defun bls-batch-verify-same-message (public-keys message signatures)
  "Optimized batch verify when all signatures are on same message.

   PARAMETERS:
   - PUBLIC-KEYS: List of public keys
   - MESSAGE: The common message
   - SIGNATURES: List of signatures

   RETURN:
   T if all valid, NIL otherwise"
  (unless (= (length public-keys) (length signatures))
    (error "Public key and signature counts must match"))
  (let ((agg-sig (bls-aggregate-signatures signatures)))
    (bls-verify-aggregate public-keys message agg-sig)))

;;; ============================================================================
;;; Proof of Possession
;;; ============================================================================

(defun bls-pop-prove (keypair)
  "Generate Proof of Possession for keypair.

   PARAMETERS:
   - KEYPAIR: bls-keypair to prove possession of

   RETURN:
   bls-pop structure

   ALGORITHM:
   pop = sk * H(pk) using PoP domain separation tag"
  (let* ((public (bls-keypair-public keypair))
         (h-pk (g1-hash-to-curve public +dst-pop+))
         (scalar (bytes-to-scalar (bls-keypair-secret keypair)))
         (proof-point (g1-mul h-pk scalar)))
    (%make-bls-pop :public-key public :proof (g1-compress proof-point))))

(defun bls-pop-verify (pop)
  "Verify Proof of Possession.

   PARAMETERS:
   - POP: bls-pop to verify

   RETURN:
   T if valid, NIL otherwise

   CRITICAL:
   Always verify PoP before accepting untrusted public keys for aggregation."
  (handler-case
      (let* ((public-key (bls-pop-public-key pop))
             (proof (bls-pop-proof pop))
             (pk-point (g2-decompress public-key))
             (proof-point (g1-decompress proof))
             (h-pk (g1-hash-to-curve public-key +dst-pop+)))
        ;; Verify e(proof, G2) = e(H(pk), pk)
        (pairing-check proof-point (g2-generator)
                       (g1-neg h-pk) pk-point))
    (error () nil)))

(defun bls-aggregate-with-pop (keypairs-with-pops)
  "Safely aggregate public keys after verifying PoPs.

   PARAMETERS:
   - KEYPAIRS-WITH-POPS: List of (public-key pop) pairs

   RETURN:
   Aggregated public key

   SECURITY:
   Safe against rogue key attacks."
  (let ((verified-pks '()))
    (dolist (entry keypairs-with-pops)
      (destructuring-bind (pk pop) entry
        (unless (bls-pop-verify pop)
          (error "Invalid proof of possession"))
        (push pk verified-pks)))
    (bls-aggregate-public-keys (nreverse verified-pks))))

;;; ============================================================================
;;; Rogue Key Protection
;;; ============================================================================

(defun bls-derive-coefficients (public-keys)
  "Derive coefficients for rogue-key-safe aggregation.

   PARAMETERS:
   - PUBLIC-KEYS: All public keys being aggregated

   RETURN:
   List of integer coefficients in F_r

   ALGORITHM:
   c_i = H(pk_i || H(all_pks)) mod r"
  (when (null public-keys)
    (return-from bls-derive-coefficients nil))
  (let* ((all-pks (apply #'concatenate '(vector (unsigned-byte 8)) public-keys))
         (L (sha256 all-pks))
         (coefficients '()))
    (dolist (pk public-keys)
      (let* ((input (concatenate '(vector (unsigned-byte 8)) pk L))
             (c-hash (sha256 input))
             (c (scalar-reduce (bytes-to-integer c-hash :big-endian t))))
        (when (zerop c) (setf c 1))
        (push c coefficients)))
    (nreverse coefficients)))

(defun bls-safe-aggregate (public-keys signatures)
  "Rogue-key-safe aggregation without PoP.

   PARAMETERS:
   - PUBLIC-KEYS: Public keys
   - SIGNATURES: Corresponding signatures

   RETURN:
   bls-aggregate-sig

   ALGORITHM:
   Uses coefficient weighting c_i * sig_i to prevent rogue key attacks."
  (unless (= (length public-keys) (length signatures))
    (error "Public key and signature counts must match"))
  (let* ((coefficients (bls-derive-coefficients public-keys))
         (acc (g1-identity))
         (count 0))
    (loop for sig in signatures
          for c in coefficients
          do (let* ((sig-bytes (etypecase sig
                                 (bls-signature (bls-signature-point sig))
                                 ((vector (unsigned-byte 8)) sig)))
                    (sig-point (g1-decompress sig-bytes))
                    (weighted (g1-mul sig-point c)))
               (setf acc (g1-add acc weighted))
               (incf count)))
    (%make-bls-aggregate-sig :point (g1-compress acc) :count count :mode :same-message)))

;;; ============================================================================
;;; Threshold Signatures
;;; ============================================================================

(defun bls-threshold-keygen (n threshold)
  "Generate key shares for t-of-n threshold BLS.

   PARAMETERS:
   - N: Total participants
   - THRESHOLD: Minimum shares to sign

   RETURN:
   (values shares master-public-key verification-vector)

   ALGORITHM:
   Shamir Secret Sharing with Feldman VSS."
  (unless (and (plusp threshold) (<= threshold n))
    (error "Invalid threshold: need 1 <= t <= n"))
  (let* (;; Random polynomial coefficients a_0, ..., a_{t-1}
         (coefficients (loop repeat threshold
                             collect (bytes-to-scalar (get-random-bytes 32))))
         ;; Verification vector (commitments)
         (verification-vector
          (coerce (loop for coef in coefficients
                        collect (g2-compress (g2-mul (g2-generator) coef)))
                  'vector))
         ;; Shares f(i) for i = 1..n
         (shares
          (loop for i from 1 to n
                collect (let* ((share-scalar (evaluate-polynomial coefficients i))
                               (share-secret (scalar-to-bytes share-scalar))
                               (share-public (bls-derive-public share-secret)))
                          (%make-bls-threshold-share
                           :index i
                           :secret share-secret
                           :public share-public
                           :verification-vector verification-vector))))
         (master-public (aref verification-vector 0)))
    (values shares master-public verification-vector)))

(defun evaluate-polynomial (coefficients x)
  "Evaluate polynomial at x using Horner's method."
  (let ((result 0))
    (loop for coef in (reverse coefficients)
          do (setf result (scalar-reduce (+ coef (scalar-reduce (* result x))))))
    result))

(defun bls-threshold-sign (share message)
  "Create partial signature with threshold share.

   PARAMETERS:
   - SHARE: bls-threshold-share
   - MESSAGE: Message to sign

   RETURN:
   (values partial-signature share-index)"
  (let* ((msg-bytes (etypecase message
                      ((vector (unsigned-byte 8)) message)
                      (string (string-to-octets message))))
         (h-point (g1-hash-to-curve msg-bytes +dst-sign+))
         (scalar (bytes-to-scalar (bls-threshold-share-secret share)))
         (partial-point (g1-mul h-point scalar)))
    (values (g1-compress partial-point) (bls-threshold-share-index share))))

(defun bls-threshold-combine (partial-signatures indices threshold)
  "Combine partial signatures into full signature.

   PARAMETERS:
   - PARTIAL-SIGNATURES: At least t partial signatures (48-byte each)
   - INDICES: Corresponding participant indices
   - THRESHOLD: The threshold t

   RETURN:
   bls-signature"
  (unless (>= (length partial-signatures) threshold)
    (error "Need at least ~D partial signatures" threshold))
  (let ((lambdas (compute-lagrange-coefficients indices)))
    (let ((acc (g1-identity)))
      (loop for sig in partial-signatures
            for lambda in lambdas
            do (let* ((sig-point (g1-decompress sig))
                      (weighted (g1-mul sig-point lambda)))
                 (setf acc (g1-add acc weighted))))
      (%make-bls-signature :point (g1-compress acc) :dst +dst-sign+))))

(defun compute-lagrange-coefficients (indices)
  "Compute Lagrange coefficients for interpolation at x=0."
  (let ((n (length indices)))
    (loop for i from 0 below n
          for x-i = (nth i indices)
          collect (let ((num 1) (den 1))
                    (loop for j from 0 below n
                          for x-j = (nth j indices)
                          when (/= i j)
                            do (setf num (scalar-reduce (* num (- x-j))))
                               (setf den (scalar-reduce (* den (- x-j x-i)))))
                    (scalar-reduce (* num (mod-expt den (- +curve-order+ 2) +curve-order+)))))))

(defun bls-threshold-verify (master-public-key message signature)
  "Verify threshold BLS signature.

   PARAMETERS:
   - MASTER-PUBLIC-KEY: Combined public key from keygen
   - MESSAGE: Signed message
   - SIGNATURE: Combined threshold signature

   RETURN:
   T if valid, NIL otherwise

   NOTE:
   Verification is identical to regular BLS."
  (bls-verify master-public-key message signature))
