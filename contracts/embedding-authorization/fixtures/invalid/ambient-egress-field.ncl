let H = import "../helpers.ncl" in
(H.policy "allow-local-without-grant" "deny" H.scope_fields "bounded-comparison-only" H.non_claims) & { ambient_egress = true }
