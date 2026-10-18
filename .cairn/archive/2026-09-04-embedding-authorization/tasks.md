# Tasks

## Phase 1: Contract and decision

- [x] [serial] Record zvec-grep reference revision `309a66995809243d3274fa8b5bea63ab11dda1a0` at `github.com/zvec-ai/zvec-grep` (v0.2.1, Apache-2.0) and the selected local-first and explicit-grant invariants in repository references. r[basalt.embedding_auth.boundary]
- [x] [serial] Add a typed Nickel embedding-authorization contract with workspace, provider, purpose, grant, and lifecycle facts. r[basalt.embedding_auth.boundary]
- [x] [depends:basalt.embedding_auth.boundary] Add pure Rust decision logic over supplied request, capability, workspace, provider, purpose, and grant facts. r[basalt.embedding_auth.decision] r[basalt.embedding_auth.freshness]

## Phase 2: Policy and scope

- [x] [serial] Implement the local-first default allowance for local embedding. r[basalt.embedding_auth.local_first]
- [x] [depends:basalt.embedding_auth.decision] Implement workspace- and purpose-scoped grant admission with over-broad denial. r[basalt.embedding_auth.scope]
- [x] [depends:basalt.embedding_auth.decision] Implement fail-closed stale, revoked, and absent-grant denial with redacted BLAKE3 receipts. r[basalt.embedding_auth.freshness]

## Phase 3: Verification

- [x] [parallel] Add positive fixtures for local embedding and one current-grant allow with a redacted receipt. r[basalt.embedding_auth.verification]
- [x] [parallel] Add negative fixtures for absent, stale, and revoked grants, wrong provider, over-broad scope, malformed policy, and authority overclaims. r[basalt.embedding_auth.verification]
- [x] [serial] Update README consumer mapping and non-claims. Add focused Cairn and Nix checks. r[basalt.embedding_auth.boundary] r[basalt.embedding_auth.verification]
- [x] [depends:basalt.embedding_auth.verification] Run focused tests before and after core changes, workspace tests, Clippy, policy checks, Cairn validation and gates, and relevant Nix checks. r[basalt.embedding_auth.verification]
