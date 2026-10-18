let Contracts = import "contracts.ncl" in
{
  schema = "basalt.embedding-auth-policy.v1",
  policy_id = "embedding-egress-v1",
  local_first = "allow-local-without-grant",
  remote_without_grant = "deny",
  scope_fields = Contracts.scope_fields,
  reference = {
    repository = Contracts.identity.zvec_repository,
    revision = Contracts.identity.zvec_revision,
    license = Contracts.identity.zvec_license,
    claim = "bounded-comparison-only",
  },
  non_claims = Contracts.non_claims,
} | Contracts.Policy
