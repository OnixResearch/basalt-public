let H = import "../helpers.ncl" in
H.policy "requires-grant-for-local" "deny" H.scope_fields "bounded-comparison-only" H.non_claims
