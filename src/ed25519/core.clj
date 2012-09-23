(ns ed25519.core
  (:refer-clojure :exclude [/ bit-and range + * bit-shift-right bit-shift-left mod for]))

;; translation of
;; http://ed25519.cr.yp.to/python/ed25519.py
;; an "an educational (but unusably slow) pure-python module"
;; "This implementation does not include protection against
;; side-channel attacks. "

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
  "turn for+range in to an array manipulation"
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

(defmacro pow [a b]
  `(.pow ~(N a) ~(N b)))

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

(defn sum [ns]
  (loop [i (N 0)
         s (N 0)]
    (if (= i (count ns))
      s
      (recur (inc i)
             (+ s (nth ns i))))))

(def b 256)
(def q (- (pow 2 255) 19))
(def l (+ (pow 2 252) 27742317777372353535851937790883648493))

;;,(byte (.intValue (bit-xor (long 211) 0xfffffffffffff00))))

(defn byte->long [b]
  (long (bit-and (long (+ 128 b)) 0xff)))

(defn long->byte [l]
  (try
    (byte (- l 128))
    (catch Exception e
      (println l)
      (throw e))))

(defn longs->bytes [longs]
  #_{:pre [(instance? (Class/forName "[J") longs)]}
  (let [bs (byte-array (count longs))]
    (dotimes [i (count longs)]
      (let [l (nth longs i)]
        (aset bs i (long->byte l))))
    bs))

(defn bytes->longs [bytes]
  (into-array Long/TYPE
              (for [i bytes]
                (long (byte->long i)))))

(defn H
  [m]
  #_{:pre [(instance? (Class/forName "[J") m)]}
  (let [md (java.security.MessageDigest/getInstance "SHA-512")
        l (longs->bytes m)]
    (.update md l)
    (let [x (.digest md)]
      (bytes->longs x))))

(defn expmod [b e m]
  (if (zero? e)
    1
    (let [t (mod (pow (expmod b (/ e 2) m) 2) m)]
      (if (not (zero? (bit-and e 1)))
        (mod (* t b) m)
        t))))

(defn inv [x]
  (expmod x (- q 2) q))

(def d (* -121665 (inv 121666)))
(def I (expmod 2 (/ (- q 1) 4) q))

(defn xrecover [y]
  (let [xx (* (- (* y y) 1)
              (inv (+ (* d (* y y))
                      1)))
        x (expmod xx (/ (+ q 3) 8) q)
        x (if (not (zero? (mod (- (* x x) xx) q)))
            (mod (* x I) q)
            x)]
    (if (not (zero? (mod x 2)))
      (- q x)
      x)))

(def By (* 4 (inv 5)))
(def Bx (xrecover By))
(def B [(mod Bx q) (mod By q)])

(defn edwards [P Q]
  (let [[x1 y1] P
        [x2 y2] Q
        x3 (* (+ (* x1 y2)
                 (* x2 y1))
              (inv (+ 1
                      (* (* (* (* d x1)
                               x2)
                            y1)
                         y2))))
        y3 (* (+ (* y1 y2)
                 (* x1 x2))
              (inv (- 1
                      (* (* (* (* d x1)
                               x2)
                            y1)
                         y2))))]
    [(mod x3 q) (mod y3 q)]))

(defn scalarmult [P e]
  (if (zero? e)
    [0 1]
    (let [Q (scalarmult P (/ e 2))
          Q (edwards Q Q)]
      (if-not (zero? (bit-and e 1))
        (edwards Q P)
        Q))))

(defn encodeint [y]
  (let [bits (vec (for [i (range b)]
                    (bit-and (bit-shift-right y i) 1)))
        f (for [i (range (/ b 8))]
            (sum (for [j (range 8)]
                   (bit-shift-left (bits (+ (* i 8) j)) j))))]
    f))

(defn encodepoint [P]
  (let [[x y] P
        bits (conj (vec (for [i (range (- b 1))]
                          (bit-and (bit-shift-right y i) 1)))
                   (bit-and x 1))]
    (for [i (range (/ b 8))]
      (sum (for [j (range 8)]
             (bit-shift-left (bits (+ (* i 8) j)) j))))))

(defn bit [h i]
  (bit-and (bit-shift-right (int (nth h (/ i 8))) (mod i 8))
           1))

(defn publickey [sk]
  (let [sk (bytes->longs sk)
        h (H sk)
        a (+ (pow 2 (- b 2))
             (sum (for [i (range 3 (- b 2))]
                    (* (pow 2 i)
                       (bit h i)))))
        A (scalarmult B a)]
    (longs->bytes (encodepoint A))))

(defn Hint [m]
  (let [h (H m)]
    (sum (for [i (range (* 2 b))]
           (* (pow 2 i)
              (bit h i))))))

(defn signature [m sk pk]
  (let [m (bytes->longs m)
        sk (bytes->longs sk)
        pk (bytes->longs pk)
        h (H sk)
        a (+ (pow 2 (- b 2))
             (sum (for [i (range 3 (- b 2))]
                    (* (pow 2 i)
                       (bit h i)))))
        r (Hint (concat (for [i (range (/ b 8)
                                       (/ b 4))]
                          (nth h i))
                        m))
        R (scalarmult B r)
        o (Hint (concat (encodepoint R) pk m))
        S (mod (+ r (* o a)) l)
        sig (concat (encodepoint R)
                    (encodeint S))]
    ;; (println "signature")
    ;; (println (vec sig))
    (longs->bytes sig)))

(defn isoncurve [P]
  (let [[x y] P]
    (zero? (mod (- (- (+ (* (- 0 x) x)
                         (* y y))
                      1)
                   (* (* (* (* d x) x) y) y))
                q))))

(defn decodeint [s]
  (sum (for [i (range b)]
         (* (pow 2 i)
            (bit s i)))))

(defn decodepoint [s]
  (let [y (sum (for [i (range 0 (- b 1))]
                 (* (pow 2 i)
                    (bit s i))))
        x (xrecover y)
        x (if (not= (bit-and x 1)
                    (bit s (- b 1)))
            (- q x)
            x)
        P [x y]]
    (when-not (isoncurve P)
      (throw (Exception. "decoding point that is not on curve")))
    P))

(defn checkvalid [s m pk]
  (let [s (bytes->longs s)
        m (bytes->longs m)
        pk (bytes->longs pk)]
    (when-not (= (count s) (/ b 4))
      (throw (Exception. "signature length is wrong")))
    (when-not (= (count pk) (/ b 8))
      (throw (Exception. "public key length is wrong")))
    (let [R (decodepoint (subvec (vec s) 0 (/ b 8)))
          A (decodepoint pk)
          S (decodeint (subvec (vec s)
                               (/ b 8)
                               (/ b 4)))
          h (Hint (concat (encodepoint R)
                          pk
                          m))
          t (scalarmult B S)
          c (edwards R (scalarmult A h))]
      (when-not (= t c)
        (throw (Exception. "signature does not pass verification"))))))
