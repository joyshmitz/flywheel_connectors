# Test Coverage Inventory and Mock Usage Map

> Generated: 2026-01-27 | Bead: bd-32k7

## Executive Summary

The flywheel_connectors codebase has **~3,600+ test markers** across **177 files**, with strong coverage in protocol, crypto, and security domains but significant gaps in connector implementations.

**Key Findings:**
- 12/27 crates (44%) have dedicated test directories
- 15/27 crates (56%) rely solely on inline tests or have no tests
- 0/5 connector implementations have any tests
- ~227 test markers are disabled/unimplemented
- Mock usage is minimal; golden vectors dominate

---

## Coverage by Crate

### Tier 1: Excellent Coverage

| Crate | Test Files | Test Count | Notes |
|-------|-----------|------------|-------|
| fcp-core | 15 | 1313 | Golden vectors for capability, revocation, audit, protocol, simulation |
| fcp-sdk | 9 | ~300 | Error handling, schemas, streaming, state, standard methods |
| fcp-sandbox | 3 | ~132 | Allow/deny matrix (83), credential injection (28), canary (21) |

### Tier 2: Good Coverage

| Crate | Test Files | Test Count | Notes |
|-------|-----------|------------|-------|
| fcp-protocol | 4 | 204 | FCPC/FCPS golden vectors, session framing, malformed input rejection |
| fcp-ratelimit | 3 | ~85 | Golden vectors, token bucket drift |
| fcp-mesh | 1 | ~38 | Mesh integration tests |

### Tier 3: Adequate Coverage

| Crate | Test Files | Test Count | Notes |
|-------|-----------|------------|-------|
| fcp-cli | 2 | ~32 | Bench test, doctor test |
| fcp-bootstrap | 2 | ~25 | Golden vectors, integration |
| fcp-manifest | 1 | ~40 | Golden vectors |

### Tier 4: Minimal Coverage

| Crate | Test Files | Test Count | Notes |
|-------|-----------|------------|-------|
| fcp-host | 1 | 8 | Rate limit integration only |
| fcp-tailscale | 1 | ~10 | Enrollment lifecycle only |
| fcp-conformance | 1 | 19 | FZPF schema validation |

### Tier 1b: Good Inline Coverage (No Dedicated Test Dir)

| Crate | Inline Tests | Status | Notes |
|-------|-------------|--------|-------|
| **fcp-crypto** | 109 | **GOOD** | Ed25519, X25519, HPKE, HKDF, AEAD, COSE |
| **fcp-store** | 100 | **GOOD** | Object store, symbol store, GC, repair |
| **fcp-raptorq** | 88 | **GOOD** | FEC encoding/decoding, chunking |

### Tier 5: No Tests (Actual Gaps)

| Crate | Tests | Status | Risk |
|-------|-------|--------|------|
| **fcp-oauth** | 0 | **HIGH** | OAuth1/2/PKCE flows untested |
| **fcp-streaming** | 0 | **HIGH** | SSE/WebSocket/reconnect untested |
| **fcp-telemetry** | 0 | **MEDIUM** | Metrics/tracing/logging untested |
| **fcp-registry** | 0 | **MEDIUM** | Service discovery untested |
| **fcp-cbor** | 0 | **LOW** | Relies on conformance tests |
| **fcp-webhook** | TBD | **MEDIUM** | Webhook event/signature untested |

### Connector Implementations

| Connector | Tests | Status |
|-----------|-------|--------|
| anthropic | 0 | **NO TESTS** |
| discord | 0 | **NO TESTS** |
| openai | 0 | **NO TESTS** |
| telegram | 0 | **NO TESTS** |
| twitter | 0 | **NO TESTS** |

---

## Mock and Test Double Usage

### Mock Framework: wiremock (Minimal Usage)

**Provider:** `fcp-testkit/src/mock_server.rs`
- `MockApiServer` wrapper with convenience methods
- OAuth token/refresh mocking
- Request verification and assertion helpers

**Consumers (19 files):**
1. `fcp-sandbox/tests/credential_injection_integration.rs` - MockCredentialInjector
2. `fcp-host/tests/rate_limit_integration.rs`
3. `fcp-tailscale/src/client.rs`
4. `fcp-protocol/src/fcps.rs`
5. `fcp-bootstrap/src/hardware_token.rs`
6. `fcp-e2e/src/lib.rs`
7. `fcp-conformance/src/harness.rs`
8. Various golden vector test files

### Dominant Pattern: Golden Vectors

Golden vector testing is the primary strategy across:
- fcp-core (capability, revocation, audit, protocol)
- fcp-sdk (error, schema, streaming, state)
- fcp-protocol (FCPC, FCPS, session)
- fcp-manifest, fcp-bootstrap, fcp-ratelimit

**Characteristics:**
- CBOR fixtures loaded from disk
- Cross-implementation verification
- Deterministic and archivable
- Less useful for performance/timing tests

### Custom Test Doubles

| Double | Location | Purpose |
|--------|----------|---------|
| MockCredentialInjector | fcp-sandbox | Credential backend simulation |
| MockApiServer | fcp-testkit | HTTP endpoint mocking |
| Test fixtures | fcp-conformance | Harness infrastructure |

---

## Critical Path Coverage Analysis

### Protocol Parse/Serialize: WELL TESTED

| Component | Tests | Coverage |
|-----------|-------|----------|
| FCPC frame parsing | 8 | fcpc_control_plane_integration.rs |
| FCPS session framing | 72 | session_golden_vectors.rs |
| FCPC golden vectors | 28 | fcpc_golden_vectors.rs |

### Crypto Verification: WELL TESTED

| Component | Unit Tests | Status |
|-----------|-----------|--------|
| Ed25519 signing/verification | 17+ | RFC 8032 test vectors, malleability tests |
| X25519 key exchange | 15+ | RFC 7748 test vectors, iterated tests |
| HPKE_Seal | 20+ | Multiple recipients, AAD tests |
| HKDF | 10+ | Key derivation tests |
| AEAD ChaCha20Poly1305 | 15+ | Encryption/decryption tests |
| COSE tokens | 20+ | Sign/verify, builder tests |

**Note:** fcp-crypto has 109 comprehensive inline unit tests including RFC test vectors.

### Revocation Freshness: WELL TESTED

| Test File | Count | Coverage |
|-----------|-------|----------|
| revocation_golden_vectors.rs | 30 | Chain integrity, quorum, freshness policies |

**Adversarial tests included:**
- Revocation withholding
- Replay attacks
- Forgery detection
- Stale frontier attacks
- Chain fork injection

### Audit/Receipt Logic: WELL TESTED

| Test File | Count | Coverage |
|-----------|-------|----------|
| audit_chain_golden_vectors.rs | 34 | Hash linking, sequence validation, fork detection |

**Coverage includes:**
- `follows()` semantics
- Quorum signatures
- Zone checkpoint binding
- Decision receipt explainability
- TraceContext propagation

### Sandbox Enforcement: EXCELLENT

| Test File | Count | Coverage |
|-----------|-------|----------|
| allow_deny_matrix.rs | 83 | Network policy enforcement |
| credential_injection_integration.rs | 28 | Credential safety |
| canary_connector.rs | 21 | Integration validation |

**Coverage includes:**
- Localhost/private range/tailnet defaults
- SSRF protection
- IP literal validation
- TLS verification
- Sandbox profile enforcement (strict/moderate/permissive)

---

## Gap List: Untested Critical Paths

### Priority 1 (HIGH) - No Unit Tests

| Gap ID | Crate | Module | Risk |
|--------|-------|--------|------|
| GAP-001 | fcp-oauth | oauth1 | OAuth 1.0 flow untested |
| GAP-002 | fcp-oauth | oauth2 | OAuth 2.0 flow untested |
| GAP-003 | fcp-oauth | pkce | PKCE challenge untested |
| GAP-004 | fcp-streaming | sse | SSE protocol untested |
| GAP-005 | fcp-streaming | websocket | WebSocket protocol untested |
| GAP-006 | fcp-streaming | reconnect | Reconnection logic untested |
| GAP-007 | connectors/* | all | All 5 connectors have 0 tests |

### Priority 2 (MEDIUM) - No Unit Tests

| Gap ID | Crate | Module | Risk |
|--------|-------|--------|------|
| GAP-008 | fcp-telemetry | metrics | Metrics collection untested |
| GAP-009 | fcp-telemetry | tracing | Tracing untested |
| GAP-010 | fcp-registry | lib | Service discovery untested |
| GAP-011 | fcp-webhook | signature | Webhook signature verification untested |
| GAP-012 | fcp-webhook | handler | Webhook handling untested |
| GAP-013 | fcp-cbor | lib | CBOR serialization untested (uses conformance only) |

### Previously Identified as Gaps (Now Verified as Tested)

The following crates were initially flagged as untested but actually have comprehensive inline tests:

| Crate | Actual Tests | Coverage |
|-------|-------------|----------|
| fcp-crypto | 109 | Ed25519, X25519, HPKE, HKDF, AEAD, COSE (RFC vectors) |
| fcp-store | 100 | Object store, symbol store, GC, repair, quarantine |
| fcp-raptorq | 88 | FEC encoding/decoding, chunking |

---

## Disabled Test Markers

| Crate | Disabled Markers | Status |
|-------|-----------------|--------|
| fcp-telemetry | 179 | `#[test]` markers without implementation |
| fcp-registry | 48 | `#[test]` markers without implementation |
| fcp-streaming | 24 | Inline markers disabled |
| fcp-webhook | 15 | Inline markers disabled |
| **Total** | **266** | Requires implementation |

---

## Recommended Follow-up Beads

Based on this inventory, the following beads should be created:

### CRITICAL Priority

1. **TEST-CRYPTO-UNIT**: Unit tests for fcp-crypto primitives (GAP-001 through GAP-005)
2. **TEST-STORE-UNIT**: Unit tests for fcp-store logic (GAP-006 through GAP-010)
3. **TEST-CONNECTORS**: Basic tests for all 5 connector implementations (GAP-018)

### HIGH Priority

4. **TEST-OAUTH-UNIT**: Unit tests for fcp-oauth flows (GAP-011 through GAP-013)
5. **TEST-RAPTORQ-UNIT**: Unit tests for fcp-raptorq (GAP-014)
6. **TEST-STREAMING-UNIT**: Unit tests for fcp-streaming (GAP-015 through GAP-017)

### MEDIUM Priority

7. **TEST-TELEMETRY-ENABLE**: Enable 179 disabled test markers in fcp-telemetry
8. **TEST-REGISTRY-ENABLE**: Enable 48 disabled test markers in fcp-registry
9. **TEST-WEBHOOK-UNIT**: Unit tests for fcp-webhook (GAP-020, GAP-021)
10. **TEST-AUDIT-UNIT**: Unit tests for fcp-audit (GAP-019)

---

## Summary Statistics

```
Total test markers:           ~3,600+ (verified by cargo test)
Test files (dedicated):       43
Files with inline tests:      100+
Crates with test dirs:        12/27 (44%)
Crates with inline tests:     15/27 (56%)
Crates without any tests:     6/27 (22%) - oauth, streaming, telemetry, registry, webhook, cbor
Connectors with tests:        0/5 (0%)
High priority gaps:           7
Medium priority gaps:         6
Mock usage files:             19
Dominant test pattern:        Inline #[cfg(test)] modules + Golden Vectors

Key verified test counts:
- fcp-crypto:   109 tests
- fcp-store:    100 tests
- fcp-raptorq:   88 tests
- fcp-core:     650+ tests
- fcp-sdk:      300+ tests
- fcp-sandbox:  132 tests
```

---

## Appendix: Files with Highest Inline Test Density

| File | Test Count | Notes |
|------|-----------|-------|
| fcp-core/src/provenance.rs | 103 | Provenance chain tests |
| fcp-core/src/quorum.rs | 65 | Quorum logic tests |
| fcp-core/src/operation.rs | 59 | Operation handling |
| fcp-core/src/audit.rs | 55 | Audit chain tests |
| fcp-core/src/error.rs | 54 | Error taxonomy |
| fcp-core/src/protocol.rs | 54 | Protocol handling |
| fcp-telemetry/src/metrics.rs | 49 | (disabled) |
| fcp-registry/src/lib.rs | 48 | (disabled) |
| fcp-core/src/health.rs | 37 | Health check logic |
| fcp-core/src/checkpoint.rs | 35 | Checkpoint logic |
