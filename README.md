# ed25519

this is a port of http://ed25519.cr.yp.to/python/ed25519.py to clojure

ed25519 is an eliptic curve signature algorithm and it can be pretty fast.

this library is most likely pretty slow

## Usage

`[ed25519 "1.1.0"]`

```clojure
ed25519.test.core> (ed25519.core/sha256 "foo")
#<byte[] [B@33fa5453>
ed25519.test.core> (ed25519.core/publickey (ed25519.core/sha256 "foo"))
#<byte[] [B@57190978>
ed25519.test.core> (count (ed25519.core/publickey (ed25519.core/sha256 "foo")))
32
ed25519.test.core> (hex-encode (ed25519.core/publickey (ed25519.core/sha256 "foo")))
"34d26579dbb456693e540672cf922f52dde0d6532e35bf06be013a7c532f20e0"
ed25519.test.core> (def sk  (ed25519.core/sha256 "foo"))
#'ed25519.test.core/sk
ed25519.test.core> (def pk (ed25519.core/publickey sk))
#'ed25519.test.core/pk
ed25519.test.core> (ed25519.core/signature (.getBytes "foo" "utf8") sk pk)
#<byte[] [B@5ad25177>
ed25519.test.core> (count (ed25519.core/signature (.getBytes "foo" "utf8") sk pk))
64
ed25519.test.core> (hex-encode (ed25519.core/signature (.getBytes "foo" "utf8") sk pk))
"2dee64fadd2c265e5a529098defa6151fe74c414b80fcceeb777b6f619fbf077756727892cee76354acc7988fb40ccb74bfede45894fd7663af58dca69ce1e01"
ed25519.test.core> (sun.misc.BASE64Encoder.)
#<BASE64Encoder sun.misc.BASE64Encoder@7727b3ce>
ed25519.test.core> (def s (ed25519.core/signature (.getBytes "foo" "utf8") sk pk))
#'ed25519.test.core/s
ed25519.test.core> (.encode (sun.misc.BASE64Encoder.) s)
Reflection warning, NO_SOURCE_FILE:1 - call to encode can't be resolved.
"Le5k+t0sJl5aUpCY3vphUf50xBS4D8zut3e29hn78Hd1ZyeJLO52NUrMeYj7QMy3S/7eRYlP12Y6\n9Y3Kac4eAQ=="
ed25519.test.core> (count *1)
89
ed25519.test.core> 
```

## Other Files 

resources/sign.input comes from http://ed25519.cr.yp.to/software.html
and is used to verify the implementation with known inputs.

## License

Copyright (C) 2013 Kevin Downey

Distributed under the Eclipse Public License, the same as Clojure.
