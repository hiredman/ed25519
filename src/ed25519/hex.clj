(ns ed25519.hex
  (:require [ed25519.core :as ed]))

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
                     (ed/long->byte
                      (+ (bit-shift-left (get hex-digit-map high-c) 4)
                         (get hex-digit-map low-c))))
               (inc (inc i))))
      result)))
