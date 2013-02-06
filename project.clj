(defproject ed25519 "1.1.0"
  :description "port of python ed25519 library"
  :url "https://github.com/hiredman/ed25519"
  :dependencies [[org.clojure/clojure "1.4.0"]]
  :test-selectors {:default (complement :regression)
                   :regression :regression
                   :all (constantly true)}
  :warn-on-reflection true)
