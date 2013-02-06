(ns ed25519.test.core
  (:require [ed25519.core :as ed]
            [ed25519.replacements :as r]
            [clojure.test :refer :all]
            [clojure.java.io :as io]
            [ed25519.hex :refer :all]))

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

(defn f [bytes]
  (let [baos (java.io.ByteArrayOutputStream.)]
    (with-open [o (java.util.zip.DeflaterOutputStream. baos)]
      (.write o bytes))
    (.toByteArray baos)))

(defn check-line [l]
  (time
   (let [x (vec (.split l ":"))
         sk (hex-decode (subs (x 0) 0 64))]
     (let [pk (ed/publickey sk)
           m (hex-decode (x 2))
           s (ed/signature m sk pk)]
       ;; (println (BigInteger.
       ;;           (ed/longs->bytes sk)))
       ;; (println
       ;;  (.encode (sun.misc.BASE64Encoder.)
       ;;           (f (into-array Byte/TYPE s))))
       (ed/checkvalid s m pk)
       (let [forged-m (ed/bytes->longs
                       (if (zero? (count m))
                         (.getBytes "x")
                         (for [i (range (count m))]
                           (.byteValue (+ (nth m i)
                                          (if (= i (dec (count m)))
                                            1
                                            0))))))]
         (is (try
               (ed/checkvalid s forged-m pk)
               false
               (catch Exception _
                 true)))
         (let [[a b _ d] x]
           (is (= a (hex-encode (concat sk pk))))
           (is (= b (hex-encode pk)))
           (is (= d (hex-encode (concat s m))))))))))

(deftest ^:regression check-test
  ;;http://ed25519.cr.yp.to/python/sign.py
  ;; on my macbook pro this takes about 12 seconds per line
  (with-open [r (io/reader (io/resource "sign.input"))]
    (doseq [l (line-seq r)]
      (check-line l))))

(deftest quick-check-test
  (with-open [r (io/reader (io/resource "sign.input"))]
    (let [ls (vec (line-seq r))]
      (doseq [l (take 5 (repeatedly #(rand-nth ls)))]
        (check-line l)))))

(deftest test-first-line
  (with-open [r (io/reader (io/resource "sign.input"))]
    (check-line (first (line-seq r)))))

(deftest t-for
  (are [x y] (and (= (vec x) (vec y))
                  (is (.isArray (class x))))
       (r/for [i (range 10)] i) (range 10)
       (r/for [i (range 10)] (inc i)) (map inc (range 10))
       (r/for [i (range 1 10)] (inc i)) (map inc (range 1 10))))
