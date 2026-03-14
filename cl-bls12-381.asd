;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-bls12-381.asd - BLS12-381 Pairing-Friendly Curve Library
;;;;
;;;; Pure Common Lisp implementation of BLS12-381 elliptic curve operations
;;;; including field arithmetic, curve operations, pairing, and BLS signatures.

(asdf:defsystem #:cl-bls12-381
  :description "BLS12-381 pairing-friendly elliptic curve with BLS signatures"
  :author "Parkian Company LLC"
  :license "MIT"
  :version "0.1.0"
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "util")
                             (:file "field")
                             (:file "curve")
                             (:file "pairing")
                             (:file "bls")))))

(asdf:defsystem #:cl-bls12-381/test
  :description "Tests for cl-bls12-381"
  :depends-on (#:cl-bls12-381)
  :components ((:module "test"
                :components ((:file "test-bls")))))
