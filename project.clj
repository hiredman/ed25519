(defproject ed25519 "2.0.0-SNAPSHOT"
  :description "port of python ed25519 library"
  :url "https://github.com/hiredman/ed25519"
  :dependencies [[org.clojure/clojure "1.4.0"]]
  :test-selectors {:default (complement :regression)
                   :regression :regression
                   :all (constantly true)}
  :warn-on-reflection true)
