(ns ed25519.core
  (:refer-clojure :exclude [/ bit-and + * bit-shift-right bit-shift-left mod
                            for])
  (:require [ed25519.replacements :refer :all]))

(set! *warn-on-reflection* true)

;; translation of
;; http://ed25519.cr.yp.to/python/ed25519.py
;; an "an educational (but unusably slow) pure-python module"
;; "This implementation does not include protection against
;; side-channel attacks. "

(defn sum [ns]
  (loop [i 0N
         s 0N]
    (if (= i (count ns))
      s
      (recur (inc i)
             (+ s (nth ns i))))))

(def b 256)
(def q (- (pow 2 255) 19))
(def l (+ (pow 2 252) 27742317777372353535851937790883648493))

(defn byte->long [b]
  (bit-and (long b) 0xff))

(defn long->byte [l]
  (unchecked-byte ^Long (long l)))

(defn longs->bytes [longs]
  (let [bs (byte-array (count longs))]
    (dotimes [i (count longs)]
      (let [l (nth longs i)]
        (aset bs i (byte (long->byte l)))))
    bs))

(defn bytes->longs [bytes]
  (into-array Long/TYPE
              (for [i bytes]
                (long (byte->long i)))))

(defn H
  [m]
  {:pre [(instance? java.lang.Number (nth m 0))]}
  (let [md (java.security.MessageDigest/getInstance "SHA-512")]
    (.update md ^bytes (longs->bytes m))
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

(defn signature [m sk′ pk]
  (let [m (bytes->longs m)
        pk (bytes->longs pk)
        h (H sk′)
        a (+ (pow 2 (- b 2))
             (sum (for [i (range 3 (- b 2))]
                    (* (pow 2 i)
                       (bit h i)))))
        r (Hint (concat (for [i (range (/ b 8) (/ b 4))]
                          (nth h i))
                        m))
        R (scalarmult B r)
        S (mod (+ r (* (Hint (concat (encodepoint R) pk m)) a)) l)]
    (longs->bytes
     (concat (encodepoint R)
             (encodeint S)))))

(defn isoncurve [P]
  (let [[x y] P]
    (zero? (mod (- (- (+ (* (- 0 x) x) (* y y)) 1)
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
      (error "decoding point that is not on curve"))
    P))

(defn checkvalid [s m pk]
  (let [s (bytes->longs s)
        m (bytes->longs m)
        pk (bytes->longs pk)]
    (when-not (= (count s) (/ b 4))
      (error "signature length is wrong"))
    (when-not (= (count pk) (/ b 8))
      (error "public key length is wrong"))
    (let [R (decodepoint (subvec (vec s) 0 (/ b 8)))
          A (decodepoint pk)
          S (decodeint (subvec (vec s)
                               (/ b 8)
                               (/ b 4)))
          h (Hint (concat (encodepoint R)
                          pk
                          m))]
      (when-not (= (scalarmult B S) (edwards R (scalarmult A h)))
        (error "signature does not pass verification")))))
