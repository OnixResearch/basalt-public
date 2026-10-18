let H = import "../helpers.ncl" in
H.policy "allow-local-without-grant" "deny" ["workspace", "provider"] "bounded-comparison-only" H.non_claims
