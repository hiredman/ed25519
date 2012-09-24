(ns ed25519.test.core
  (:require [ed25519.core :as ed]
            [ed25519.replacements :as r]
            [clojure.test :refer :all]
            [clojure.java.io :as io]))

(def hex-digits
  [\0 \1 \2 \3 \4 \5 \6 \7 \8 \9
   \a \b \c \d \e \f])

(def hex-digit-map
  (into (hash-map) (map-indexed
                    (fn [i v] [v i])
                    hex-digits)))

(defn hex-encode [bytes]
  (let [buf (StringBuffer.)]
    (dotimes [i (count bytes)]
      (let [b (nth bytes i)
            low (bit-and b 0x0f)
            high (bit-and (bit-shift-right b 4) 0x0f)]
        (.append buf (nth hex-digits high))
        (.append buf (nth hex-digits low))))
    (.toString buf)))

(defn hex-decode [hex]
  (loop [result []
         i 0]
    (if (> (count hex) i)
      (let [high-c (nth hex i)
            low-c (nth hex (inc i))]
        (recur (conj result
                     (+ (bit-shift-left (get hex-digit-map high-c) 4)
                        (get hex-digit-map low-c)))
               (inc (inc i))))
      result)))

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
  ;; on my macbook pro this takes about 12 seconds per line
  (with-open [r (io/reader (io/resource "sign.input"))]
    (doseq [l (line-seq r)]
      (time
       (let [x (vec (.split l ":"))
             sk (hex-decode (subs (x 0) 0 64))
             pk (ed/publickey sk)
             m (hex-decode (x 2))
             s (ed/signature m sk pk)]
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
             (is (= d (hex-encode (concat s m)))))))))))

(deftest t-for
  (are [x y] (and (= (vec x) (vec y))
                  (is (.isArray (class x))))
       (r/for [i (range 10)] i) (range 10)
       (r/for [i (range 10)] (inc i)) (map inc (range 10))
       (r/for [i (range 1 10)] (inc i)) (map inc (range 1 10))))
