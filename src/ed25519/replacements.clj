(ns ed25519.replacements
  (:refer-clojure :exclude [/ bit-and range + * bit-shift-right bit-shift-left
                            mod for concat]))

(set! *warn-on-reflection* true)

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
             a# (make-array Object c#)]
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
  `(quot ~a ~b))

(defmacro bit-op [op-name method-name & [arg]]
  (let [op (symbol "clojure.core" (name op-name))
        b (gensym 'b)]
    `(defn ~op-name [a# ~b]
       (if (instance? clojure.lang.BigInt a#)
         (let [^clojure.lang.BigInt n# a#]
           (if (.bipart n#)
             (clojure.lang.BigInt/fromBigInteger
              (. (.bipart n#) ~method-name
                 ~(if arg
                    `(~arg ~b)
                    b)))
             (~op (.lpart n#) ~b)))
         (~op a# ~b)))))

(bit-op bit-and and BigInteger/valueOf)

(bit-op bit-shift-left shiftLeft int)

(bit-op bit-shift-right shiftRight int)

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

(defmacro gen-concat [& args]
  (let [arr (gensym 'arr)]
    `(let [size# ~(conj (for [x args] `(count ~x)) 'clojure.core/+)
           ~arr (make-array Object size#)
           ~'a-i 0
           ~@(for [a args
                   x ['a-i `(loop [a-i# 0
                                   arr-i# ~'a-i]
                              (if (> (count ~a) a-i#)
                                (do
                                  (aset ~arr arr-i# (aget ~a a-i#))
                                  (recur (inc a-i#) (inc arr-i#)))
                                arr-i#))]]
               x)]
       ~arr)))

(defn concat
  ([a b]
     (gen-concat a b))
  ([a b c]
     (gen-concat a b c)))
