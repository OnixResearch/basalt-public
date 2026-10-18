//! Deterministic embedding-authorization policy.
//!
//! The core evaluates supplied request, workspace, provider, purpose, and
//! grant facts only. It performs no network, transport, key-store, clock,
//! revocation-store, or filesystem effect. Local embedding stays allowed
//! without any grant. Remote embedding requires an explicit current grant
//! bound to one workspace, one provider, and one purpose.
// r[impl basalt.embedding_auth.boundary]
// r[impl basalt.embedding_auth.local_first]
// r[impl basalt.embedding_auth.decision]
// r[impl basalt.embedding_auth.scope]
// r[impl basalt.embedding_auth.freshness]

use serde::{Deserialize, Serialize};
use std::fmt;

const POLICY_SCHEMA: &str = "basalt.embedding-auth-policy.v1";
const POLICY_ID: &str = "embedding-egress-v1";
const RECEIPT_SCHEMA: &str = "basalt.embedding-auth-decision.v1";
const RECEIPT_DOMAIN: &[u8] = b"basalt/embedding-auth-decision/v1";
const ZVEC_REFERENCE_REPOSITORY: &str = "https://github.com/zvec-ai/zvec-grep";
const ZVEC_REFERENCE_REVISION: &str = "309a66995809243d3274fa8b5bea63ab11dda1a0";
const ZVEC_REFERENCE_LICENSE: &str = "Apache-2.0";
const MAXIMUM_POLICY_BYTES: usize = 16_384;
const MAXIMUM_FACT_BYTES: usize = 4_096;
const BLAKE3_PREFIX: &str = "blake3:";
const NON_CLAIM_COUNT: usize = 6;
const POLICY_NON_CLAIMS: [&str; NON_CLAIM_COUNT] = [
    "an embedding allow does not transfer data or execute an embedder",
    "endpoint bearer authentication never authorizes remote embedding",
    "provider correctness and embedding quality stay outside the policy",
    "key custody and transport remain consumer-owned",
    "revocation currentness beyond supplied lifecycle facts remains consumer-owned",
    "the zvec-grep reference is a bounded comparison, not parity or ported code",
];
const SCOPE_FIELDS: [&str; 3] = ["workspace", "provider", "purpose"];

/// Checked-in Nickel-exported embedding-authorization policy.
pub const DEFAULT_EMBEDDING_AUTH_POLICY_JSON: &str =
    include_str!("../contracts/embedding-authorization/generated/policy.json");

/// Closed embedding location admitted by Basalt policy.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EmbeddingMode {
    Local,
    Remote,
}

impl EmbeddingMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }
}

/// Closed grant lifecycle observation supplied by the consumer.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GrantLifecycle {
    Current,
    Stale,
    Revoked,
}

impl GrantLifecycle {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Stale => "stale",
            Self::Revoked => "revoked",
        }
    }
}

/// Explicit metadata-promotion boundary for one embedding request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EmbeddingBoundary {
    #[default]
    None,
    TreatsEndpointBearerAsEgressAuthority,
    PromotesAmbientEgress,
}

impl EmbeddingBoundary {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::TreatsEndpointBearerAsEgressAuthority => {
                "treats-endpoint-bearer-as-egress-authority"
            }
            Self::PromotesAmbientEgress => "promotes-ambient-egress",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum RequiredLocalFirst {
    AllowLocalWithoutGrant,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum RequiredRemoteDefault {
    Deny,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceDto {
    repository: String,
    revision: String,
    license: String,
    claim: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDto {
    schema: String,
    policy_id: String,
    local_first: RequiredLocalFirst,
    remote_without_grant: RequiredRemoteDefault,
    scope_fields: Vec<String>,
    reference: ReferenceDto,
    non_claims: Vec<String>,
}

/// Validated embedding-authorization policy value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddingAuthPolicy {
    identity: [u8; blake3::OUT_LEN],
}

impl EmbeddingAuthPolicy {
    #[must_use]
    pub const fn identity(&self) -> &[u8; blake3::OUT_LEN] {
        &self.identity
    }
}

/// Stable policy-admission failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddingAuthPolicyError {
    Oversized,
    Malformed,
    SchemaMismatch,
    IdentityMismatch,
    ScopeFieldMismatch,
    ReferenceMismatch,
    NonClaimsWeakened,
}

impl fmt::Display for EmbeddingAuthPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Oversized => "embedding-auth policy exceeds its byte limit",
            Self::Malformed => "embedding-auth policy is malformed",
            Self::SchemaMismatch => "embedding-auth policy schema does not match",
            Self::IdentityMismatch => "embedding-auth policy identity does not match",
            Self::ScopeFieldMismatch => "embedding-auth policy scope fields do not match",
            Self::ReferenceMismatch => "embedding-auth comparison reference does not match",
            Self::NonClaimsWeakened => "embedding-auth policy non-claims were weakened",
        })
    }
}

impl std::error::Error for EmbeddingAuthPolicyError {}

/// Parse one exact Nickel-exported embedding-authorization policy.
///
/// # Errors
///
/// Returns a stable error for oversized, malformed, stale, or weakened policy.
///
/// # Panics
///
/// Panics only if the closed local-first and remote-default enums admit a
/// value other than the reviewed allow-local and deny-remote defaults.
pub fn parse_embedding_auth_policy(
    json: &str,
) -> Result<EmbeddingAuthPolicy, EmbeddingAuthPolicyError> {
    if json.len() > MAXIMUM_POLICY_BYTES {
        return Err(EmbeddingAuthPolicyError::Oversized);
    }
    let dto: PolicyDto =
        serde_json::from_str(json).map_err(|_| EmbeddingAuthPolicyError::Malformed)?;
    // The closed single-variant enums already reject every other value as
    // malformed; the asserts document the reviewed local-first and remote-deny
    // defaults the decision relies on.
    assert_eq!(dto.local_first, RequiredLocalFirst::AllowLocalWithoutGrant);
    assert_eq!(dto.remote_without_grant, RequiredRemoteDefault::Deny);
    if dto.schema != POLICY_SCHEMA {
        return Err(EmbeddingAuthPolicyError::SchemaMismatch);
    }
    if dto.policy_id != POLICY_ID {
        return Err(EmbeddingAuthPolicyError::IdentityMismatch);
    }
    if dto.scope_fields != SCOPE_FIELDS.map(str::to_owned) {
        return Err(EmbeddingAuthPolicyError::ScopeFieldMismatch);
    }
    if dto.reference.repository != ZVEC_REFERENCE_REPOSITORY
        || dto.reference.revision != ZVEC_REFERENCE_REVISION
        || dto.reference.license != ZVEC_REFERENCE_LICENSE
        || dto.reference.claim != "bounded-comparison-only"
    {
        return Err(EmbeddingAuthPolicyError::ReferenceMismatch);
    }
    if dto.non_claims != POLICY_NON_CLAIMS.map(str::to_owned) {
        return Err(EmbeddingAuthPolicyError::NonClaimsWeakened);
    }
    Ok(EmbeddingAuthPolicy {
        identity: *blake3::hash(json.as_bytes()).as_bytes(),
    })
}

/// Explicit embedding request facts that grant content cannot widen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddingAuthRequest<'a> {
    mode: EmbeddingMode,
    workspace_root: Option<&'a str>,
    provider: Option<&'a str>,
    purpose: Option<&'a str>,
    boundary: EmbeddingBoundary,
}

impl<'a> EmbeddingAuthRequest<'a> {
    #[must_use]
    pub const fn new(mode: EmbeddingMode, boundary: EmbeddingBoundary) -> Self {
        Self {
            mode,
            workspace_root: None,
            provider: None,
            purpose: None,
            boundary,
        }
    }

    #[must_use]
    pub const fn with_workspace_root(mut self, workspace_root: &'a str) -> Self {
        self.workspace_root = Some(workspace_root);
        self
    }

    #[must_use]
    pub const fn with_provider(mut self, provider: &'a str) -> Self {
        self.provider = Some(provider);
        self
    }

    #[must_use]
    pub const fn with_purpose(mut self, purpose: &'a str) -> Self {
        self.purpose = Some(purpose);
        self
    }
}

/// Consumer-supplied grant fact with one exact scope and lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddingGrant<'a> {
    grant_id: &'a str,
    workspace_root: &'a str,
    provider: &'a str,
    purpose: &'a str,
    lifecycle: GrantLifecycle,
}

impl<'a> EmbeddingGrant<'a> {
    #[must_use]
    pub const fn new(
        grant_id: &'a str,
        workspace_root: &'a str,
        provider: &'a str,
        purpose: &'a str,
        lifecycle: GrantLifecycle,
    ) -> Self {
        Self {
            grant_id,
            workspace_root,
            provider,
            purpose,
            lifecycle,
        }
    }
}

/// Stable Basalt embedding-authorization denial issue.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EmbeddingAuthIssue {
    FactOversized,
    AuthorityOverclaim,
    MissingScopeFact,
    AbsentGrant,
    GrantLifecycleDenied,
    OverBroadScope,
    ScopeMismatch,
}

impl EmbeddingAuthIssue {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FactOversized => "embedding-fact-oversized",
            Self::AuthorityOverclaim => "embedding-authority-overclaim",
            Self::MissingScopeFact => "embedding-scope-fact-missing",
            Self::AbsentGrant => "embedding-grant-absent",
            Self::GrantLifecycleDenied => "embedding-grant-lifecycle-denied",
            Self::OverBroadScope => "embedding-grant-scope-over-broad",
            Self::ScopeMismatch => "embedding-grant-scope-mismatch",
        }
    }
}

/// Metadata-only embedding-authorization decision receipt.
///
/// Receipt text carries BLAKE3 fact identities only. Raw workspace, provider,
/// purpose, and grant text never enters receipt fields.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EmbeddingAuthReceipt {
    schema: String,
    allowed: bool,
    issue: Option<EmbeddingAuthIssue>,
    mode: String,
    boundary: String,
    workspace_root_blake3: String,
    provider_blake3: String,
    purpose_blake3: String,
    grant_id_blake3: String,
    grant_lifecycle: String,
    policy_blake3: String,
    reference_repository: String,
    reference_revision: String,
    reference_license: String,
    supported_claim: String,
    non_claims: Vec<String>,
    receipt_blake3: String,
}

impl EmbeddingAuthReceipt {
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.allowed
    }

    #[must_use]
    pub const fn issue(&self) -> Option<EmbeddingAuthIssue> {
        self.issue
    }
}

/// Private-construction admitted embedding-authorization statement.
#[derive(Debug)]
pub struct EmbeddingAuthDecision {
    receipt: EmbeddingAuthReceipt,
}

impl EmbeddingAuthDecision {
    #[must_use]
    pub const fn receipt(&self) -> &EmbeddingAuthReceipt {
        &self.receipt
    }
}

/// Failed embedding-authorization evaluation with redacted evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddingAuthFailure {
    issue: EmbeddingAuthIssue,
    receipt: Box<EmbeddingAuthReceipt>,
}

impl EmbeddingAuthFailure {
    #[must_use]
    pub const fn issue(&self) -> EmbeddingAuthIssue {
        self.issue
    }

    #[must_use]
    pub const fn receipt(&self) -> &EmbeddingAuthReceipt {
        &self.receipt
    }
}

impl fmt::Display for EmbeddingAuthFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "embedding-authorization denied: {}",
            self.issue.code()
        )
    }
}

impl std::error::Error for EmbeddingAuthFailure {}

/// Evaluate embedding-authorization policy over supplied facts.
///
/// Local embedding is allowed without any grant. Remote embedding requires an
/// explicit current grant bound to exactly the request workspace, provider,
/// and purpose. Stale, revoked, absent, and over-broad grants fail closed.
///
/// # Errors
///
/// Returns a redacted typed denial for every missing, stale, over-broad,
/// mismatched, or promoted input.
pub fn evaluate_embedding_authorization<'a>(
    policy: &EmbeddingAuthPolicy,
    request: EmbeddingAuthRequest<'a>,
    grant: Option<&EmbeddingGrant<'a>>,
) -> Result<EmbeddingAuthDecision, EmbeddingAuthFailure> {
    let issue = first_issue(request, grant);
    let receipt = build_receipt(policy, request, grant, issue);
    if let Some(issue) = issue {
        Err(EmbeddingAuthFailure {
            issue,
            receipt: Box::new(receipt),
        })
    } else {
        Ok(EmbeddingAuthDecision { receipt })
    }
}

fn first_issue<'a>(
    request: EmbeddingAuthRequest<'a>,
    grant: Option<&EmbeddingGrant<'a>>,
) -> Option<EmbeddingAuthIssue> {
    if fact_oversized(request.workspace_root)
        || fact_oversized(request.provider)
        || fact_oversized(request.purpose)
    {
        return Some(EmbeddingAuthIssue::FactOversized);
    }
    if let Some(grant) = grant
        && (fact_oversized(Some(grant.grant_id))
            || fact_oversized(Some(grant.workspace_root))
            || fact_oversized(Some(grant.provider))
            || fact_oversized(Some(grant.purpose)))
    {
        return Some(EmbeddingAuthIssue::FactOversized);
    }
    if request.boundary != EmbeddingBoundary::None {
        return Some(EmbeddingAuthIssue::AuthorityOverclaim);
    }
    if request.mode == EmbeddingMode::Local {
        return None;
    }
    if request.workspace_root.is_none_or(str::is_empty)
        || request.provider.is_none_or(str::is_empty)
        || request.purpose.is_none_or(str::is_empty)
    {
        return Some(EmbeddingAuthIssue::MissingScopeFact);
    }
    let Some(grant) = grant else {
        return Some(EmbeddingAuthIssue::AbsentGrant);
    };
    if grant.lifecycle != GrantLifecycle::Current {
        return Some(EmbeddingAuthIssue::GrantLifecycleDenied);
    }
    if grant.grant_id.is_empty()
        || grant.workspace_root.is_empty()
        || grant.provider.is_empty()
        || grant.purpose.is_empty()
    {
        return Some(EmbeddingAuthIssue::OverBroadScope);
    }
    if request.workspace_root != Some(grant.workspace_root)
        || request.provider != Some(grant.provider)
        || request.purpose != Some(grant.purpose)
    {
        return Some(EmbeddingAuthIssue::ScopeMismatch);
    }
    None
}

fn fact_oversized(fact: Option<&str>) -> bool {
    fact.is_some_and(|value| value.len() > MAXIMUM_FACT_BYTES)
}

fn build_receipt<'a>(
    policy: &EmbeddingAuthPolicy,
    request: EmbeddingAuthRequest<'a>,
    grant: Option<&EmbeddingGrant<'a>>,
    issue: Option<EmbeddingAuthIssue>,
) -> EmbeddingAuthReceipt {
    let allowed = issue.is_none();
    let supported_claim = match (request.mode, allowed) {
        (EmbeddingMode::Local, true) => "local-embedding-without-egress-authority",
        (EmbeddingMode::Remote, true) => "current-workspace-scoped-embedding-grant-admitted",
        (_, false) => "no-embedding-egress-authority-admitted",
    };
    let receipt_digest = receipt_digest(policy, request, grant, allowed, issue, supported_claim);
    EmbeddingAuthReceipt {
        schema: RECEIPT_SCHEMA.to_owned(),
        allowed,
        issue,
        mode: request.mode.as_str().to_owned(),
        boundary: request.boundary.as_str().to_owned(),
        workspace_root_blake3: fact_identity(request.workspace_root),
        provider_blake3: fact_identity(request.provider),
        purpose_blake3: fact_identity(request.purpose),
        grant_id_blake3: fact_identity(grant.map(|value| value.grant_id)),
        grant_lifecycle: grant
            .map_or("absent", |value| value.lifecycle.as_str())
            .to_owned(),
        policy_blake3: format_identity(blake3::Hash::from_bytes(policy.identity).to_hex().as_ref()),
        reference_repository: ZVEC_REFERENCE_REPOSITORY.to_owned(),
        reference_revision: ZVEC_REFERENCE_REVISION.to_owned(),
        reference_license: ZVEC_REFERENCE_LICENSE.to_owned(),
        supported_claim: supported_claim.to_owned(),
        non_claims: POLICY_NON_CLAIMS.map(str::to_owned).to_vec(),
        receipt_blake3: format_identity(blake3::Hash::from_bytes(receipt_digest).to_hex().as_ref()),
    }
}

fn receipt_digest<'a>(
    policy: &EmbeddingAuthPolicy,
    request: EmbeddingAuthRequest<'a>,
    grant: Option<&EmbeddingGrant<'a>>,
    allowed: bool,
    issue: Option<EmbeddingAuthIssue>,
    supported_claim: &str,
) -> [u8; blake3::OUT_LEN] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, RECEIPT_DOMAIN);
    hash_field(&mut hasher, &[u8::from(allowed)]);
    hash_field(
        &mut hasher,
        issue.map_or("none", EmbeddingAuthIssue::code).as_bytes(),
    );
    hash_field(&mut hasher, request.mode.as_str().as_bytes());
    hash_field(&mut hasher, request.boundary.as_str().as_bytes());
    hash_fact(&mut hasher, request.workspace_root);
    hash_fact(&mut hasher, request.provider);
    hash_fact(&mut hasher, request.purpose);
    hash_fact(&mut hasher, grant.map(|value| value.grant_id));
    hash_fact(&mut hasher, grant.map(|value| value.workspace_root));
    hash_fact(&mut hasher, grant.map(|value| value.provider));
    hash_fact(&mut hasher, grant.map(|value| value.purpose));
    hash_field(
        &mut hasher,
        grant
            .map_or("absent", |value| value.lifecycle.as_str())
            .as_bytes(),
    );
    hash_field(&mut hasher, &policy.identity);
    hash_field(&mut hasher, supported_claim.as_bytes());
    for non_claim in POLICY_NON_CLAIMS {
        hash_field(&mut hasher, non_claim.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn hash_fact(hasher: &mut blake3::Hasher, fact: Option<&str>) {
    hash_field(hasher, fact.unwrap_or("absent").as_bytes());
}

fn fact_identity(fact: Option<&str>) -> String {
    format_identity(
        blake3::hash(fact.unwrap_or("absent").as_bytes())
            .to_hex()
            .as_ref(),
    )
}

fn format_identity(hex: &str) -> String {
    format!("{BLAKE3_PREFIX}{hex}")
}

fn hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("embedding receipt fields must fit u64");
    hasher.update(&length.to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKSPACE: &str = "cap://workspace/docs";
    const PROVIDER: &str = "embedding-provider-v1";
    const PURPOSE: &str = "workspace-retrieval";

    #[test]
    fn local_mode_allows_without_any_grant() {
        let policy = parse_embedding_auth_policy(DEFAULT_EMBEDDING_AUTH_POLICY_JSON)
            .expect("checked embedding policy must parse");
        let request = EmbeddingAuthRequest::new(EmbeddingMode::Local, EmbeddingBoundary::None);
        let decision = evaluate_embedding_authorization(&policy, request, None)
            .expect("local embedding must be allowed without a grant");
        assert!(decision.receipt().is_allowed());
        assert_eq!(decision.receipt().issue(), None);
    }

    #[test]
    fn oversized_request_and_grant_facts_fail_closed() {
        let policy = parse_embedding_auth_policy(DEFAULT_EMBEDDING_AUTH_POLICY_JSON)
            .expect("checked embedding policy must parse");
        let oversized = "x".repeat(MAXIMUM_FACT_BYTES + 1);
        let request = EmbeddingAuthRequest::new(EmbeddingMode::Remote, EmbeddingBoundary::None)
            .with_workspace_root(oversized.as_str())
            .with_provider(PROVIDER)
            .with_purpose(PURPOSE);
        assert_eq!(
            evaluate_embedding_authorization(&policy, request, None)
                .expect_err("oversized request fact must deny")
                .issue(),
            EmbeddingAuthIssue::FactOversized
        );
        let request = EmbeddingAuthRequest::new(EmbeddingMode::Remote, EmbeddingBoundary::None)
            .with_workspace_root(WORKSPACE)
            .with_provider(PROVIDER)
            .with_purpose(PURPOSE);
        let oversized_grant = EmbeddingGrant::new(
            "grant-1",
            WORKSPACE,
            PROVIDER,
            &oversized,
            GrantLifecycle::Current,
        );
        assert_eq!(
            evaluate_embedding_authorization(&policy, request, Some(&oversized_grant))
                .expect_err("oversized grant fact must deny")
                .issue(),
            EmbeddingAuthIssue::FactOversized
        );
    }
}
