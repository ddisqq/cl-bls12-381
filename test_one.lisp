;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

(load "cl-bls12-381.asd")
(handler-case
  (progn
    (asdf:test-system :cl-bls12-381/test)
    (format t "PASS~%"))
  (error (e)
    (format t "FAIL~%")))
(quit)
