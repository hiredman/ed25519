(ns ed25519.replacements
  (:refer-clojure :exclude [/ bit-and range + * bit-shift-right bit-shift-left mod for]))

(defn N [n]
  (if (number? n)
    (.toBigInteger (bigint n))
    `(N ~n)))

(set! *data-readers*
      (assoc *data-readers*
        'hiredman/N #'N))

(defn range [& args]
  (map N (apply clojure.core/range args)))

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
      `(let [c# (- ~high ~low)
             ;; :/ Object
             a# (make-array Number c#)]
         (loop [i# 0]
           (if (> c# i#)
             (let [~name i#]
               (aset a# i# ~body)
               (recur (inc i#)))
             a#))))
    `(clojure.core/for ~binding ~body)))

(defmacro + [a b]
  `(.add ~(N a) ~(N b)))

(defmacro / [a b]
  `(.divide ~(N a) ~(N b)))

(defmacro bit-and [a b]
  `(.and ~(N a) ~(N b)))

(defmacro * [a b]
  `(.multiply ~(N a) ~(N b)))

(defmacro bit-shift-left [a b]
  `(.shiftLeft ~(N a) ~(N b)))

(defmacro bit-shift-right [a b]
  `(.shiftRight ~(N a) ~(N b)))

(defmacro mod [a b]
  `(.mod ~(N a) ~(N b)))
