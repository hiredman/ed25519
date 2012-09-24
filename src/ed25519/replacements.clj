(ns ed25519.replacements
  (:refer-clojure :exclude [/ bit-and range + * bit-shift-right bit-shift-left mod for]))

;; (defn ^BigInteger N [n]
;;   (if (number? n)
;;     (.toBigInteger (bigint n))
;;     (with-meta `(N ~n) {:tag BigInteger})))

;; (set! *data-readers*
;;       (assoc *data-readers*
;;         'hiredman/N #'N))

;; (defn range [& args]
;;   (map N (apply clojure.core/range args)))

(defmacro for
  "turn for+range in to an array map"
  [[name value :as binding] body]
  (if  (and (= 2 (count binding))
            (seq? value)
            (= 'range (first value)))
    (let [x (rest value)
          [low high] (if (= 2 (count x))
                       x
                       [0 (first x)])]
      `(let [h# ~high
             l# ~low
             c# (- h# l#)
             a# (make-array Number c#)]
         (loop [array-index# 0
                n# l#]
           (if (> c# array-index#)
             (let [~name n#]
               (aset a# array-index# ~body)
               (recur (inc array-index#)
                      (inc n#)))
             a#))))
    `(clojure.core/for ~binding ~body)))

(defmacro + [a b]
  `(clojure.core/+' ~a ~b))

(defmacro / [a b]
  `(bigint (clojure.core// ~a ~b)))

(defn bit-and [a b]
  (if (instance? clojure.lang.BigInt a)
    (let [^clojure.lang.BigInt n a]
      (if (.bipart n)
        (clojure.lang.BigInt/fromBigInteger
         (.and (.bipart n) (BigInteger/valueOf b)))
        (clojure.core/bit-and (.lpart n) b)))
    (clojure.core/bit-and a b)))

(defn bit-shift-left [a b]
  (if (instance? clojure.lang.BigInt a)
    (let [^clojure.lang.BigInt n a]
      (if (.bipart n)
        (clojure.lang.BigInt/fromBigInteger
         (.shiftLeft (.bipart n) b))
        (clojure.core/bit-shift-left (.lpart n) b)))
    (clojure.core/bit-shift-left a b)))

(defn bit-shift-right [a b]
  (if (instance? clojure.lang.BigInt a)
    (let [^clojure.lang.BigInt n a]
      (if (.bipart n)
        (clojure.lang.BigInt/fromBigInteger
         (.shiftRight (.bipart n) b))
        (clojure.core/bit-shift-right (.lpart n) b)))
    (clojure.core/bit-shift-right a b)))

(defmacro * [a b]
  `(clojure.core/*' ~a ~b))

(defmacro mod [a b]
  `(clojure.core/mod ~a ~b))

(defn pow
  "not a real pow"
  [a b]
  (loop [result 1N
         b b]
    (if (zero? b)
      result
      (recur (* result a) (dec b)))))

(defmacro error [s]
  `(throw (Exception. ~s)))
