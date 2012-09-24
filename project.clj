(defproject ed25519 "1.0.0-SNAPSHOT"
  :description "FIXME: write description"
  :dependencies [[org.clojure/clojure "1.4.0"]]
  :test-selectors {:default (complement :regression)
                   :regression :regression
                   :all (constantly true)})
