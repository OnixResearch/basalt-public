let H = import "../helpers.ncl" in
H.policy "allow-local-without-grant" "deny" H.scope_fields "bounded-comparison-only" [
  "an embedding allow does not transfer data or execute an embedder",
  "endpoint bearer authentication never authorizes remote embedding",
  "provider correctness and embedding quality stay outside the policy",
  "key custody and transport remain consumer-owned",
  "revocation currentness beyond supplied lifecycle facts remains consumer-owned",
]
