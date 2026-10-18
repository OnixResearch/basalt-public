// r[verify basalt.embedding_auth.boundary]
// r[verify basalt.embedding_auth.local_first]
// r[verify basalt.embedding_auth.decision]
// r[verify basalt.embedding_auth.scope]
// r[verify basalt.embedding_auth.freshness]
// r[verify basalt.embedding_auth.verification]

use basalt::embedding_authorization::{
    DEFAULT_EMBEDDING_AUTH_POLICY_JSON, EmbeddingAuthIssue, EmbeddingAuthPolicyError,
    EmbeddingAuthRequest, EmbeddingBoundary, EmbeddingGrant, EmbeddingMode, GrantLifecycle,
    evaluate_embedding_authorization, parse_embedding_auth_policy,
};
use serde_json::Value;

const WORKSPACE: &str = "cap://workspace/docs";
const OTHER_WORKSPACE: &str = "cap://workspace/other";
const PROVIDER: &str = "embedding-provider-v1";
const OTHER_PROVIDER: &str = "embedding-provider-v2";
const PURPOSE: &str = "workspace-retrieval";
const OTHER_PURPOSE: &str = "archive-indexing";
const GRANT_ID: &str = "grant-2026-09-04";
const QUERY_SENTINEL: &str = "quarterly-retrieval-query-text";
const STEEL_FIXTURES_JSON: &str =
    include_str!("../contracts/embedding-authorization/generated/steel-fixtures.json");

fn admitted_policy() -> basalt::embedding_authorization::EmbeddingAuthPolicy {
    parse_embedding_auth_policy(DEFAULT_EMBEDDING_AUTH_POLICY_JSON)
        .expect("checked embedding policy must parse")
}

const fn remote_request() -> EmbeddingAuthRequest<'static> {
    EmbeddingAuthRequest::new(EmbeddingMode::Remote, EmbeddingBoundary::None)
        .with_workspace_root(WORKSPACE)
        .with_provider(PROVIDER)
        .with_purpose(PURPOSE)
}

const fn scoped_grant(lifecycle: GrantLifecycle) -> EmbeddingGrant<'static> {
    EmbeddingGrant::new(GRANT_ID, WORKSPACE, PROVIDER, PURPOSE, lifecycle)
}

#[test]
fn local_embedding_is_allowed_without_any_grant() {
    let policy = admitted_policy();
    let request = EmbeddingAuthRequest::new(EmbeddingMode::Local, EmbeddingBoundary::None);
    let decision = evaluate_embedding_authorization(&policy, request, None)
        .expect("local embedding must not need a grant");
    assert!(decision.receipt().is_allowed());
    assert_eq!(decision.receipt().issue(), None);
    let serialized = serde_json::to_string(decision.receipt()).expect("receipt JSON");
    assert!(serialized.contains("local-embedding-without-egress-authority"));
}

#[test]
fn current_exact_grant_allows_remote_transfer_with_redacted_receipt() {
    let policy = admitted_policy();
    let decision = evaluate_embedding_authorization(
        &policy,
        remote_request(),
        Some(&scoped_grant(GrantLifecycle::Current)),
    )
    .expect("exact current grant must admit remote embedding");
    assert!(decision.receipt().is_allowed());
    assert_eq!(decision.receipt().issue(), None);
    let serialized = serde_json::to_string(decision.receipt()).expect("receipt JSON");
    assert!(serialized.contains("current-workspace-scoped-embedding-grant-admitted"));
    assert!(!serialized.contains(WORKSPACE));
    assert!(!serialized.contains(PROVIDER));
    assert!(!serialized.contains(PURPOSE));
    assert!(!serialized.contains(GRANT_ID));
    assert!(!serialized.contains(QUERY_SENTINEL));
    assert!(serialized.contains("blake3:"));
}

#[test]
fn absent_stale_and_revoked_grants_fail_closed() {
    let policy = admitted_policy();
    let absent = evaluate_embedding_authorization(&policy, remote_request(), None)
        .expect_err("absent grant must deny");
    assert_eq!(absent.issue(), EmbeddingAuthIssue::AbsentGrant);
    assert!(!absent.receipt().is_allowed());

    let stale = evaluate_embedding_authorization(
        &policy,
        remote_request(),
        Some(&scoped_grant(GrantLifecycle::Stale)),
    )
    .expect_err("stale grant must deny");
    assert_eq!(stale.issue(), EmbeddingAuthIssue::GrantLifecycleDenied);

    let revoked = evaluate_embedding_authorization(
        &policy,
        remote_request(),
        Some(&scoped_grant(GrantLifecycle::Revoked)),
    )
    .expect_err("revoked grant must deny");
    assert_eq!(revoked.issue(), EmbeddingAuthIssue::GrantLifecycleDenied);
}

#[test]
fn mismatched_over_broad_and_missing_scope_facts_fail_closed() {
    let policy = admitted_policy();

    let wrong_workspace = EmbeddingAuthRequest::new(EmbeddingMode::Remote, EmbeddingBoundary::None)
        .with_workspace_root(OTHER_WORKSPACE)
        .with_provider(PROVIDER)
        .with_purpose(PURPOSE);
    assert_eq!(
        evaluate_embedding_authorization(
            &policy,
            wrong_workspace,
            Some(&scoped_grant(GrantLifecycle::Current))
        )
        .expect_err("wrong workspace must deny")
        .issue(),
        EmbeddingAuthIssue::ScopeMismatch
    );

    let wrong_provider = EmbeddingAuthRequest::new(EmbeddingMode::Remote, EmbeddingBoundary::None)
        .with_workspace_root(WORKSPACE)
        .with_provider(OTHER_PROVIDER)
        .with_purpose(PURPOSE);
    assert_eq!(
        evaluate_embedding_authorization(
            &policy,
            wrong_provider,
            Some(&scoped_grant(GrantLifecycle::Current))
        )
        .expect_err("wrong provider must deny")
        .issue(),
        EmbeddingAuthIssue::ScopeMismatch
    );

    let wrong_purpose = EmbeddingAuthRequest::new(EmbeddingMode::Remote, EmbeddingBoundary::None)
        .with_workspace_root(WORKSPACE)
        .with_provider(PROVIDER)
        .with_purpose(OTHER_PURPOSE);
    assert_eq!(
        evaluate_embedding_authorization(
            &policy,
            wrong_purpose,
            Some(&scoped_grant(GrantLifecycle::Current))
        )
        .expect_err("wrong purpose must deny")
        .issue(),
        EmbeddingAuthIssue::ScopeMismatch
    );

    let over_broad = EmbeddingGrant::new(GRANT_ID, WORKSPACE, "", "", GrantLifecycle::Current);
    assert_eq!(
        evaluate_embedding_authorization(&policy, remote_request(), Some(&over_broad))
            .expect_err("over-broad grant must deny")
            .issue(),
        EmbeddingAuthIssue::OverBroadScope
    );

    let missing_purpose = EmbeddingAuthRequest::new(EmbeddingMode::Remote, EmbeddingBoundary::None)
        .with_workspace_root(WORKSPACE)
        .with_provider(PROVIDER);
    assert_eq!(
        evaluate_embedding_authorization(
            &policy,
            missing_purpose,
            Some(&scoped_grant(GrantLifecycle::Current))
        )
        .expect_err("missing purpose must deny")
        .issue(),
        EmbeddingAuthIssue::MissingScopeFact
    );

    let empty_purpose = EmbeddingAuthRequest::new(EmbeddingMode::Remote, EmbeddingBoundary::None)
        .with_workspace_root(WORKSPACE)
        .with_provider(PROVIDER)
        .with_purpose("");
    assert_eq!(
        evaluate_embedding_authorization(
            &policy,
            empty_purpose,
            Some(&scoped_grant(GrantLifecycle::Current))
        )
        .expect_err("empty purpose must deny")
        .issue(),
        EmbeddingAuthIssue::MissingScopeFact
    );
}

#[test]
fn bearer_and_ambient_authority_overclaims_fail_closed() {
    let policy = admitted_policy();
    let bearer = EmbeddingAuthRequest::new(
        EmbeddingMode::Remote,
        EmbeddingBoundary::TreatsEndpointBearerAsEgressAuthority,
    )
    .with_workspace_root(WORKSPACE)
    .with_provider(PROVIDER)
    .with_purpose(PURPOSE);
    assert_eq!(
        evaluate_embedding_authorization(
            &policy,
            bearer,
            Some(&scoped_grant(GrantLifecycle::Current))
        )
        .expect_err("bearer promotion must deny")
        .issue(),
        EmbeddingAuthIssue::AuthorityOverclaim
    );

    let ambient = EmbeddingAuthRequest::new(
        EmbeddingMode::Remote,
        EmbeddingBoundary::PromotesAmbientEgress,
    )
    .with_workspace_root(WORKSPACE)
    .with_provider(PROVIDER)
    .with_purpose(PURPOSE);
    assert_eq!(
        evaluate_embedding_authorization(
            &policy,
            ambient,
            Some(&scoped_grant(GrantLifecycle::Current))
        )
        .expect_err("ambient egress promotion must deny")
        .issue(),
        EmbeddingAuthIssue::AuthorityOverclaim
    );
}

#[test]
fn policy_rejects_malformed_weakened_and_overclaiming_variants() {
    let base: Value =
        serde_json::from_str(DEFAULT_EMBEDDING_AUTH_POLICY_JSON).expect("checked policy JSON");

    let mut extra_field = base.clone();
    extra_field["ambient_egress"] = Value::Bool(true);
    assert_eq!(
        parse_embedding_auth_policy(&serde_json::to_string(&extra_field).expect("JSON")),
        Err(EmbeddingAuthPolicyError::Malformed)
    );

    let mut local_first_off = base.clone();
    local_first_off["local_first"] = Value::String("requires-grant-for-local".to_owned());
    assert_eq!(
        parse_embedding_auth_policy(&serde_json::to_string(&local_first_off).expect("JSON")),
        Err(EmbeddingAuthPolicyError::Malformed)
    );

    let mut remote_default_allow = base.clone();
    remote_default_allow["remote_without_grant"] = Value::String("allow".to_owned());
    assert_eq!(
        parse_embedding_auth_policy(&serde_json::to_string(&remote_default_allow).expect("JSON")),
        Err(EmbeddingAuthPolicyError::Malformed)
    );

    let mut missing_scope = base.clone();
    missing_scope["scope_fields"] =
        serde_json::from_value(Value::Array(vec![Value::String("workspace".to_owned())]))
            .expect("scope array");
    assert_eq!(
        parse_embedding_auth_policy(&serde_json::to_string(&missing_scope).expect("JSON")),
        Err(EmbeddingAuthPolicyError::ScopeFieldMismatch)
    );

    let mut parity = base.clone();
    parity["reference"]["claim"] = Value::String("parity".to_owned());
    assert_eq!(
        parse_embedding_auth_policy(&serde_json::to_string(&parity).expect("JSON")),
        Err(EmbeddingAuthPolicyError::ReferenceMismatch)
    );

    let mut stale_reference = base.clone();
    stale_reference["reference"]["revision"] = Value::String("0".repeat(40));
    assert_eq!(
        parse_embedding_auth_policy(&serde_json::to_string(&stale_reference).expect("JSON")),
        Err(EmbeddingAuthPolicyError::ReferenceMismatch)
    );

    let mut weakened = base.clone();
    weakened["non_claims"]
        .as_array_mut()
        .expect("non-claims array")
        .pop();
    assert_eq!(
        parse_embedding_auth_policy(&serde_json::to_string(&weakened).expect("JSON")),
        Err(EmbeddingAuthPolicyError::NonClaimsWeakened)
    );

    let mut wrong_schema = base.clone();
    wrong_schema["schema"] = Value::String("basalt.embedding-auth-policy.v2".to_owned());
    assert_eq!(
        parse_embedding_auth_policy(&serde_json::to_string(&wrong_schema).expect("JSON")),
        Err(EmbeddingAuthPolicyError::SchemaMismatch)
    );

    let mut wrong_id = base;
    wrong_id["policy_id"] = Value::String("embedding-egress-v2".to_owned());
    assert_eq!(
        parse_embedding_auth_policy(&serde_json::to_string(&wrong_id).expect("JSON")),
        Err(EmbeddingAuthPolicyError::IdentityMismatch)
    );
}

#[test]
fn decisions_are_deterministic_across_repeated_evaluations() {
    let policy = admitted_policy();
    let first = evaluate_embedding_authorization(
        &policy,
        remote_request(),
        Some(&scoped_grant(GrantLifecycle::Current)),
    )
    .expect("first evaluation must admit");
    let second = evaluate_embedding_authorization(
        &policy,
        remote_request(),
        Some(&scoped_grant(GrantLifecycle::Current)),
    )
    .expect("second evaluation must admit");
    assert_eq!(first.receipt(), second.receipt());

    let first_deny = evaluate_embedding_authorization(&policy, remote_request(), None)
        .expect_err("first denial must hold");
    let second_deny = evaluate_embedding_authorization(&policy, remote_request(), None)
        .expect_err("second denial must hold");
    assert_eq!(first_deny.receipt(), second_deny.receipt());
}

#[test]
fn steel_fixture_matrix_replays_to_the_expected_decisions() {
    let fixtures: Value =
        serde_json::from_str(STEEL_FIXTURES_JSON).expect("Steel fixture JSON must parse");
    let cases = fixtures["cases"].as_array().expect("cases array");
    assert!(cases.len() >= 9, "fixture matrix must stay broad");
    let policy = admitted_policy();
    for case in cases {
        let id = case["id"].as_str().expect("case id");
        let mode = if case["mode"].as_str() == Some("local") {
            EmbeddingMode::Local
        } else {
            EmbeddingMode::Remote
        };
        let boundary = match case["boundary"].as_str().expect("boundary") {
            "treats-endpoint-bearer-as-egress-authority" => {
                EmbeddingBoundary::TreatsEndpointBearerAsEgressAuthority
            }
            "promotes-ambient-egress" => EmbeddingBoundary::PromotesAmbientEgress,
            _ => EmbeddingBoundary::None,
        };
        let mut request = EmbeddingAuthRequest::new(mode, boundary);
        if case["workspace_present"].as_bool().expect("workspace flag") {
            request = request.with_workspace_root(WORKSPACE);
        }
        if case["provider_present"].as_bool().expect("provider flag") {
            request = request.with_provider(PROVIDER);
        }
        if case["purpose_present"].as_bool().expect("purpose flag") {
            request = request.with_purpose(PURPOSE);
        }
        let grant = match case["grant"].as_str().expect("grant vocabulary") {
            "absent" => None,
            "current" => Some(scoped_grant(GrantLifecycle::Current)),
            "stale" => Some(scoped_grant(GrantLifecycle::Stale)),
            "revoked" => Some(scoped_grant(GrantLifecycle::Revoked)),
            "wrong-provider" => Some(EmbeddingGrant::new(
                GRANT_ID,
                WORKSPACE,
                OTHER_PROVIDER,
                PURPOSE,
                GrantLifecycle::Current,
            )),
            "over-broad" => Some(EmbeddingGrant::new(
                GRANT_ID,
                WORKSPACE,
                "",
                "",
                GrantLifecycle::Current,
            )),
            other => panic!("unknown grant vocabulary: {other}"),
        };
        let expected_issue = case["issue"].as_str().expect("issue code");
        let expected_allowed = case["expected"].as_str().expect("expected decision") == "allow";
        let outcome = evaluate_embedding_authorization(&policy, request, grant.as_ref());
        match outcome {
            Ok(decision) => {
                assert!(expected_allowed, "case {id} must allow");
                assert_eq!(decision.receipt().issue(), None, "case {id}");
            }
            Err(failure) => {
                assert!(!expected_allowed, "case {id} must deny");
                assert!(!failure.receipt().is_allowed(), "case {id}");
                assert_eq!(failure.issue().code(), expected_issue, "case {id}");
            }
        }
    }
}
