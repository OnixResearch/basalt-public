let ZvecRepository = "https://github.com/zvec-ai/zvec-grep" in
let ZvecRevision = "309a66995809243d3274fa8b5bea63ab11dda1a0" in
let ZvecLicense = "Apache-2.0" in
let ScopeFields = ["workspace", "provider", "purpose"] in
let NonClaims = [
  "an embedding allow does not transfer data or execute an embedder",
  "endpoint bearer authentication never authorizes remote embedding",
  "provider correctness and embedding quality stay outside the policy",
  "key custody and transport remain consumer-owned",
  "revocation currentness beyond supplied lifecycle facts remains consumer-owned",
  "the zvec-grep reference is a bounded comparison, not parity or ported code",
] in
let SteelCases = [
  { id = "local-allow", mode = "local", workspace_present = true, provider_present = true, purpose_present = true, grant = "absent", boundary = "none", expected = "allow", issue = "none" },
  { id = "current-grant-allow", mode = "remote", workspace_present = true, provider_present = true, purpose_present = true, grant = "current", boundary = "none", expected = "allow", issue = "none" },
  { id = "absent-grant", mode = "remote", workspace_present = true, provider_present = true, purpose_present = true, grant = "absent", boundary = "none", expected = "deny", issue = "embedding-grant-absent" },
  { id = "stale-grant", mode = "remote", workspace_present = true, provider_present = true, purpose_present = true, grant = "stale", boundary = "none", expected = "deny", issue = "embedding-grant-lifecycle-denied" },
  { id = "revoked-grant", mode = "remote", workspace_present = true, provider_present = true, purpose_present = true, grant = "revoked", boundary = "none", expected = "deny", issue = "embedding-grant-lifecycle-denied" },
  { id = "wrong-provider", mode = "remote", workspace_present = true, provider_present = true, purpose_present = true, grant = "wrong-provider", boundary = "none", expected = "deny", issue = "embedding-grant-scope-mismatch" },
  { id = "over-broad-scope", mode = "remote", workspace_present = true, provider_present = true, purpose_present = true, grant = "over-broad", boundary = "none", expected = "deny", issue = "embedding-grant-scope-over-broad" },
  { id = "bearer-overclaim", mode = "remote", workspace_present = true, provider_present = true, purpose_present = true, grant = "current", boundary = "treats-endpoint-bearer-as-egress-authority", expected = "deny", issue = "embedding-authority-overclaim" },
  { id = "ambient-overclaim", mode = "remote", workspace_present = true, provider_present = true, purpose_present = true, grant = "current", boundary = "promotes-ambient-egress", expected = "deny", issue = "embedding-authority-overclaim" },
  { id = "missing-purpose", mode = "remote", workspace_present = true, provider_present = true, purpose_present = false, grant = "absent", boundary = "none", expected = "deny", issue = "embedding-scope-fact-missing" },
] in
let exact_fields = fun allowed value =>
  std.is_record value
  && std.array.length (std.record.fields value) == std.array.length allowed
  && std.array.all (fun field => std.array.elem field allowed) (std.record.fields value)
in
let field = fun name value => std.record.get name value in
let valid_fixture_suite = fun value =>
  exact_fields ["schema", "policy_id", "cases", "non_claims"] value
  && field "schema" value == "basalt.embedding-auth-steel-fixtures.v1"
  && field "policy_id" value == "embedding-egress-v1"
  && field "cases" value == SteelCases
  && field "non_claims" value == NonClaims
in
let valid_policy = fun value =>
  exact_fields [
    "schema",
    "policy_id",
    "local_first",
    "remote_without_grant",
    "scope_fields",
    "reference",
    "non_claims",
  ] value
  && field "schema" value == "basalt.embedding-auth-policy.v1"
  && field "policy_id" value == "embedding-egress-v1"
  && field "local_first" value == "allow-local-without-grant"
  && field "remote_without_grant" value == "deny"
  && field "scope_fields" value == ScopeFields
  && exact_fields ["repository", "revision", "license", "claim"] (field "reference" value)
  && field "repository" (field "reference" value) == ZvecRepository
  && field "revision" (field "reference" value) == ZvecRevision
  && field "license" (field "reference" value) == ZvecLicense
  && field "claim" (field "reference" value) == "bounded-comparison-only"
  && field "non_claims" value == NonClaims
in
{
  Policy = std.contract.from_predicate valid_policy,
  SteelFixtureSuite = std.contract.from_predicate valid_fixture_suite,
  steel_cases = SteelCases,
  identity = {
    zvec_repository = ZvecRepository,
    zvec_revision = ZvecRevision,
    zvec_license = ZvecLicense,
  },
  scope_fields = ScopeFields,
  non_claims = NonClaims,
}
