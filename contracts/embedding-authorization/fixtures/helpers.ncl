let Contracts = import "../contracts.ncl" in
{
  policy = fun local_first remote_default scope_fields reference_claim non_claims =>
    {
      schema = "basalt.embedding-auth-policy.v1",
      policy_id = "embedding-egress-v1",
      local_first = local_first,
      remote_without_grant = remote_default,
      scope_fields = scope_fields,
      reference = {
        repository = Contracts.identity.zvec_repository,
        revision = Contracts.identity.zvec_revision,
        license = Contracts.identity.zvec_license,
        claim = reference_claim,
      },
      non_claims = non_claims,
    } | Contracts.Policy,
  identity = Contracts.identity,
  scope_fields = Contracts.scope_fields,
  non_claims = Contracts.non_claims,
}
