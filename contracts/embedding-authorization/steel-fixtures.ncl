let Contracts = import "contracts.ncl" in
{
  schema = "basalt.embedding-auth-steel-fixtures.v1",
  policy_id = "embedding-egress-v1",
  cases = Contracts.steel_cases,
  non_claims = Contracts.non_claims,
} | Contracts.SteelFixtureSuite
