let H = import "../helpers.ncl" in
H.policy "allow-local-without-grant" "allow" H.scope_fields "bounded-comparison-only" H.non_claims
