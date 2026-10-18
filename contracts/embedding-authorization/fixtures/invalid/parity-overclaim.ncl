let H = import "../helpers.ncl" in
H.policy "allow-local-without-grant" "deny" H.scope_fields "parity" H.non_claims
