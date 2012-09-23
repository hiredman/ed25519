(ns ed25519.test.core
  (:require [ed25519.core :as ed]
            [clojure.test :refer :all]
            [clojure.java.io :as io])
  (:import (org.apache.commons.codec.binary Hex)))

(deftest check-params
  ;;http://ed25519.cr.yp.to/python/checkparams.py
  (is (>= ed/b 10))
  (is (= (* 2 ed/b)
         (* 8 (count (ed/H (ed/bytes->longs (.getBytes "hash input")))))))
  (is (= 1 (ed/expmod 2 (- ed/q 1) ed/q)))
  (is (= 1 (mod ed/q 4)))
  (is (= 1 (ed/expmod 2 (- ed/l 1) ed/l)))
  (is (>= ed/l (Math/pow 2 (- ed/b 4))))
  (is (<= ed/l (Math/pow 2 (- ed/b 3))))
  (is (= (ed/expmod ed/d (/ (- ed/q 1) 2) ed/q) (- ed/q 1)))
  (is (= (ed/expmod ed/I 2 ed/q) (- ed/q 1)))
  (is (ed/isoncurve ed/B))
  (is (= (ed/scalarmult ed/B ed/l) [0 1])))

(deftest check-test
  ;;http://ed25519.cr.yp.to/python/sign.py
  (with-open [r (io/reader (io/resource "sign.input"))]
    (doseq [[idx l] (map-indexed vector (line-seq r))
            :let [x (vec (.split l ":"))
                  sk (Hex/decodeHex (.toCharArray (subs (x 0) 0 64)))
                  pk (ed/publickey sk)
                  m (Hex/decodeHex (.toCharArray (x 2)))
                  s (ed/signature m sk pk)]]
      (println idx)
      (println (Hex/encodeHexString
                (into-array Byte/TYPE s)))
      (ed/checkvalid s m pk)
      (let [forged-m (ed/bytes->longs
                      (if (zero? (count m))
                        (.getBytes "x")
                        (for [i (range (count m))]
                          (byte(+ (nth m i)
                                  (if (= i (dec (count m)))
                                    1
                                    0))))))]
        (is (try
              (ed/checkvalid s forged-m pk)
              false
              (catch Exception _
                  true)))
        (is (= (get x 0) (Hex/encodeHexString
                          (into-array Byte/TYPE
                                      (concat sk pk)))))
        (is (= (get x 1) (Hex/encodeHexString pk)))
        (is (= (get x 3) (Hex/encodeHexString
                          (into-array Byte/TYPE
                                      (concat s m)))))
        (System/exit 0)))))
