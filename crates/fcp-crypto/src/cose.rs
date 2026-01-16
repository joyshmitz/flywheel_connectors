//! COSE/CWT helpers for FCP2 capability tokens.
//!
//! Implements `COSE_Sign1` tokens with deterministic CBOR payload maps
//! as required for `CapabilityToken` verification.
//!
//! ## Security Requirements
//! - Verify signature BEFORE trusting/parsing untrusted claims
//! - Extract protected `kid` and route to correct issuance pubkey
//! - Use deterministic CBOR for signing

use crate::ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use crate::error::{CryptoError, CryptoResult};
use crate::kid::KeyId;
use chrono::{DateTime, Utc};
use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, iana};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// COSE algorithm identifier for Ed25519.
pub const COSE_ALG_EDDSA: i64 = iana::Algorithm::EdDSA as i64;

/// CWT claim keys (registered claims from RFC 8392).
pub mod cwt_claims {
    /// Issuer claim key.
    pub const ISS: i64 = 1;
    /// Subject claim key.
    pub const SUB: i64 = 2;
    /// Audience claim key.
    pub const AUD: i64 = 3;
    /// Expiration time claim key.
    pub const EXP: i64 = 4;
    /// Not before claim key.
    pub const NBF: i64 = 5;
    /// Issued at claim key.
    pub const IAT: i64 = 6;
    /// CWT ID (token identifier) claim key.
    pub const CTI: i64 = 7;
}

/// FCP2 private claim keys (negative numbers per CWT spec).
pub mod fcp2_claims {
    /// Capability ID claim.
    pub const CAPABILITY_ID: i64 = -65537;
    /// Zone ID claim.
    pub const ZONE_ID: i64 = -65538;
    /// Allowed operations claim (array of operation IDs).
    pub const OPERATIONS: i64 = -65539;
    /// Principal ID claim.
    pub const PRINCIPAL_ID: i64 = -65540;
    /// Delegation depth claim.
    pub const DELEGATION_DEPTH: i64 = -65541;
    /// Parent token ID claim (for delegated tokens).
    pub const PARENT_TOKEN: i64 = -65542;
    /// Issuing node ID claim.
    pub const ISS_NODE: i64 = -65543;
    /// Binary audience (`ObjectId`) claim.
    pub const AUD_BINARY: i64 = -65544;
    /// Grant Object IDs claim.
    pub const GRANT_OBJECT_IDS: i64 = -65545;
    /// Holder node ID claim.
    pub const HOLDER_NODE: i64 = -65546;
    /// Checkpoint ID claim.
    pub const CHK_ID: i64 = -65547;
    /// Checkpoint sequence claim.
    pub const CHK_SEQ: i64 = -65548;
    /// Capability constraints claim.
    pub const CONSTRAINTS: i64 = -65549;
    /// Granted capabilities (array of `CapabilityGrant`).
    pub const GRANTS: i64 = -65550;
    /// Instance ID claim.
    pub const INSTANCE_ID: i64 = -65551;
}

/// CWT (CBOR Web Token) claims map.
///
/// Claims are stored in a `BTreeMap` to ensure deterministic serialization.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CwtClaims {
    claims: BTreeMap<i64, ciborium::Value>,
}

impl CwtClaims {
    /// Create empty claims.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set issuer (iss) claim.
    #[must_use]
    pub fn issuer(mut self, iss: &str) -> Self {
        self.claims
            .insert(cwt_claims::ISS, ciborium::Value::Text(iss.into()));
        self
    }

    /// Set subject (sub) claim.
    #[must_use]
    pub fn subject(mut self, sub: &str) -> Self {
        self.claims
            .insert(cwt_claims::SUB, ciborium::Value::Text(sub.into()));
        self
    }

    /// Set audience (aud) claim.
    #[must_use]
    pub fn audience(mut self, aud: &str) -> Self {
        self.claims
            .insert(cwt_claims::AUD, ciborium::Value::Text(aud.into()));
        self
    }

    /// Set expiration time (exp) claim.
    #[must_use]
    pub fn expiration(mut self, exp: DateTime<Utc>) -> Self {
        self.claims.insert(
            cwt_claims::EXP,
            ciborium::Value::Integer(exp.timestamp().into()),
        );
        self
    }

    /// Set not-before (nbf) claim.
    #[must_use]
    pub fn not_before(mut self, nbf: DateTime<Utc>) -> Self {
        self.claims.insert(
            cwt_claims::NBF,
            ciborium::Value::Integer(nbf.timestamp().into()),
        );
        self
    }

    /// Set issued-at (iat) claim.
    #[must_use]
    pub fn issued_at(mut self, iat: DateTime<Utc>) -> Self {
        self.claims.insert(
            cwt_claims::IAT,
            ciborium::Value::Integer(iat.timestamp().into()),
        );
        self
    }

    /// Set token ID (cti) claim.
    #[must_use]
    pub fn token_id(mut self, cti: &[u8]) -> Self {
        self.claims
            .insert(cwt_claims::CTI, ciborium::Value::Bytes(cti.to_vec()));
        self
    }

    /// Set FCP2 capability ID claim.
    #[must_use]
    pub fn capability_id(mut self, cap_id: &str) -> Self {
        self.claims.insert(
            fcp2_claims::CAPABILITY_ID,
            ciborium::Value::Text(cap_id.into()),
        );
        self
    }

    /// Set FCP2 zone ID claim.
    #[must_use]
    pub fn zone_id(mut self, zone_id: &str) -> Self {
        self.claims
            .insert(fcp2_claims::ZONE_ID, ciborium::Value::Text(zone_id.into()));
        self
    }

    /// Set FCP2 allowed operations claim.
    #[must_use]
    pub fn operations(mut self, ops: &[&str]) -> Self {
        let values: Vec<ciborium::Value> = ops
            .iter()
            .map(|s| ciborium::Value::Text((*s).into()))
            .collect();
        self.claims
            .insert(fcp2_claims::OPERATIONS, ciborium::Value::Array(values));
        self
    }

    /// Set FCP2 principal ID claim.
    #[must_use]
    pub fn principal_id(mut self, principal: &str) -> Self {
        self.claims.insert(
            fcp2_claims::PRINCIPAL_ID,
            ciborium::Value::Text(principal.into()),
        );
        self
    }

    /// Set FCP2 issuing node ID.
    #[must_use]
    pub fn issuing_node(mut self, node_id: &str) -> Self {
        self.claims
            .insert(fcp2_claims::ISS_NODE, ciborium::Value::Text(node_id.into()));
        self
    }

    /// Set FCP2 binary audience (`ObjectId`).
    #[must_use]
    pub fn audience_binary(mut self, object_id: &[u8]) -> Self {
        self.claims.insert(
            fcp2_claims::AUD_BINARY,
            ciborium::Value::Bytes(object_id.to_vec()),
        );
        self
    }

    /// Set FCP2 grant object IDs.
    #[must_use]
    pub fn grant_objects(mut self, object_ids: &[&[u8]]) -> Self {
        let values: Vec<ciborium::Value> = object_ids
            .iter()
            .map(|id| ciborium::Value::Bytes(id.to_vec()))
            .collect();
        self.claims.insert(
            fcp2_claims::GRANT_OBJECT_IDS,
            ciborium::Value::Array(values),
        );
        self
    }

    /// Set FCP2 holder node ID.
    #[must_use]
    pub fn holder_node(mut self, node_id: &str) -> Self {
        self.claims.insert(
            fcp2_claims::HOLDER_NODE,
            ciborium::Value::Text(node_id.into()),
        );
        self
    }

    /// Set FCP2 checkpoint ID and sequence.
    #[must_use]
    pub fn checkpoint(mut self, id: &[u8], seq: u64) -> Self {
        self.claims
            .insert(fcp2_claims::CHK_ID, ciborium::Value::Bytes(id.to_vec()));
        self.claims
            .insert(fcp2_claims::CHK_SEQ, ciborium::Value::Integer(seq.into()));
        self
    }

    /// Set custom claim.
    #[must_use]
    pub fn custom(mut self, key: i64, value: ciborium::Value) -> Self {
        self.claims.insert(key, value);
        self
    }

    /// Get a claim value.
    #[must_use]
    pub fn get(&self, key: i64) -> Option<&ciborium::Value> {
        self.claims.get(&key)
    }

    /// Get issuer claim as string.
    #[must_use]
    pub fn get_issuer(&self) -> Option<&str> {
        self.get(cwt_claims::ISS).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get subject claim as string.
    #[must_use]
    pub fn get_subject(&self) -> Option<&str> {
        self.get(cwt_claims::SUB).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get expiration as timestamp.
    #[must_use]
    pub fn get_expiration(&self) -> Option<i64> {
        self.get(cwt_claims::EXP).and_then(|v| match v {
            ciborium::Value::Integer(i) => i64::try_from(*i).ok(),
            _ => None,
        })
    }

    /// Get not-before as timestamp.
    #[must_use]
    pub fn get_not_before(&self) -> Option<i64> {
        self.get(cwt_claims::NBF).and_then(|v| match v {
            ciborium::Value::Integer(i) => i64::try_from(*i).ok(),
            _ => None,
        })
    }

    /// Get capability ID.
    #[must_use]
    pub fn get_capability_id(&self) -> Option<&str> {
        self.get(fcp2_claims::CAPABILITY_ID).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get zone ID.
    #[must_use]
    pub fn get_zone_id(&self) -> Option<&str> {
        self.get(fcp2_claims::ZONE_ID).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get holder node ID (NORMATIVE).
    ///
    /// When this claim is set, requests using this token MUST include
    /// a `holder_proof` signature from the specified node.
    #[must_use]
    pub fn get_holder_node(&self) -> Option<&str> {
        self.get(fcp2_claims::HOLDER_NODE).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get JWT ID (jti claim).
    ///
    /// The unique identifier for this token, used in `holder_proof` binding.
    #[must_use]
    pub fn get_jti(&self) -> Option<&[u8]> {
        self.get(cwt_claims::CTI).and_then(|v| match v {
            ciborium::Value::Bytes(b) => Some(b.as_slice()),
            _ => None,
        })
    }

    /// Encode claims to deterministic CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_cbor(&self) -> CryptoResult<Vec<u8>> {
        // Convert BTreeMap to CBOR map (sorted keys = deterministic)
        let map: Vec<(ciborium::Value, ciborium::Value)> = self
            .claims
            .iter()
            .map(|(k, v)| (ciborium::Value::Integer((*k).into()), v.clone()))
            .collect();

        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(map), &mut bytes)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        Ok(bytes)
    }

    /// Decode claims from CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_cbor(bytes: &[u8]) -> CryptoResult<Self> {
        let value: ciborium::Value = ciborium::from_reader(bytes)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        let ciborium::Value::Map(map) = value else {
            return Err(CryptoError::SerializationError("expected CBOR map".into()));
        };

        let mut claims = BTreeMap::new();
        for (k, v) in map {
            let key = match k {
                ciborium::Value::Integer(i) => i64::try_from(i)
                    .map_err(|_| CryptoError::SerializationError("invalid claim key".into()))?,
                _ => {
                    return Err(CryptoError::SerializationError(
                        "claim key must be integer".into(),
                    ));
                }
            };
            claims.insert(key, v);
        }

        Ok(Self { claims })
    }
}

/// `COSE_Sign1` token for FCP2 capabilities.
#[derive(Debug, Clone)]
pub struct CoseToken {
    inner: CoseSign1,
}

impl CoseToken {
    /// Create and sign a new `COSE_Sign1` token.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(signing_key: &Ed25519SigningKey, claims: &CwtClaims) -> CryptoResult<Self> {
        let payload = claims.to_cbor()?;
        let kid = signing_key.key_id();

        // Build protected header with algorithm and key ID
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(kid.as_bytes().to_vec())
            .build();

        // Build a partial CoseSign1 to get the to-be-signed bytes
        let mut cose_sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .build();

        // Get the to-be-signed bytes (Sig_structure)
        let tbs = cose_sign1.tbs_data(&[]);

        // Sign the TBS data
        let signature = signing_key.sign(&tbs);

        // Set the signature
        cose_sign1.signature = signature.to_bytes().to_vec();

        Ok(Self { inner: cose_sign1 })
    }

    /// Verify the token signature and extract claims.
    ///
    /// **IMPORTANT:** This verifies the signature BEFORE returning claims,
    /// as required by the spec.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> CryptoResult<CwtClaims> {
        // Extract signature
        let signature = Ed25519Signature::try_from_slice(&self.inner.signature)?;

        // Recreate to-be-signed bytes
        let tbs = self.inner.tbs_data(&[]);

        // Verify signature FIRST
        verifying_key.verify(&tbs, &signature)?;

        // Only after verification, parse the payload
        let payload = self
            .inner
            .payload
            .as_ref()
            .ok_or_else(|| CryptoError::MissingField("payload".into()))?;

        CwtClaims::from_cbor(payload)
    }

    /// Verify using a key lookup function.
    ///
    /// The lookup function receives the KID from the protected header
    /// and should return the corresponding verifying key.
    ///
    /// # Errors
    ///
    /// Returns an error if the KID is missing, key lookup fails, or verification fails.
    pub fn verify_with_lookup<F>(&self, key_lookup: F) -> CryptoResult<CwtClaims>
    where
        F: FnOnce(&KeyId) -> Option<Ed25519VerifyingKey>,
    {
        // Extract KID from protected header
        let kid_bytes = self.get_key_id()?;
        let kid = KeyId::try_from_slice(&kid_bytes)?;

        // Look up the verifying key
        let verifying_key =
            key_lookup(&kid).ok_or_else(|| CryptoError::InvalidKeyId("key not found".into()))?;

        self.verify(&verifying_key)
    }

    /// Get the key ID from the protected header.
    ///
    /// # Errors
    ///
    /// Returns an error if the KID is missing.
    pub fn get_key_id(&self) -> CryptoResult<Vec<u8>> {
        let kid = &self.inner.protected.header.key_id;
        if kid.is_empty() {
            Err(CryptoError::MissingField("kid in protected header".into()))
        } else {
            Ok(kid.clone())
        }
    }

    /// Encode to CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_cbor(&self) -> CryptoResult<Vec<u8>> {
        self.inner
            .clone()
            .to_vec()
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Decode from CBOR bytes.
    ///
    /// **NOTE:** This only parses the structure. You MUST call `verify()`
    /// before trusting any claims.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_cbor(bytes: &[u8]) -> CryptoResult<Self> {
        let inner = CoseSign1::from_slice(bytes)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Validate token timing (exp, nbf).
    ///
    /// # Errors
    ///
    /// Returns an error if the token is expired or not yet valid.
    pub fn validate_timing(claims: &CwtClaims, now: DateTime<Utc>) -> CryptoResult<()> {
        let now_ts = now.timestamp();

        // Check expiration
        if let Some(exp) = claims.get_expiration() {
            if now_ts >= exp {
                return Err(CryptoError::TokenExpired);
            }
        }

        // Check not-before
        if let Some(nbf) = claims.get_not_before() {
            if now_ts < nbf {
                return Err(CryptoError::TokenNotYetValid);
            }
        }

        Ok(())
    }
}

/// Build a capability token with standard FCP2 claims.
pub struct CapabilityTokenBuilder {
    claims: CwtClaims,
}

impl CapabilityTokenBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            claims: CwtClaims::new(),
        }
    }

    /// Set the capability ID.
    #[must_use]
    pub fn capability_id(mut self, id: &str) -> Self {
        self.claims = self.claims.capability_id(id);
        self
    }

    /// Set the zone ID.
    #[must_use]
    pub fn zone_id(mut self, zone: &str) -> Self {
        self.claims = self.claims.zone_id(zone);
        self
    }

    /// Set the principal ID (who this token is for).
    #[must_use]
    pub fn principal(mut self, principal: &str) -> Self {
        self.claims = self.claims.principal_id(principal);
        self
    }

    /// Set allowed operations.
    #[must_use]
    pub fn operations(mut self, ops: &[&str]) -> Self {
        self.claims = self.claims.operations(ops);
        self
    }

    /// Set issuing node.
    #[must_use]
    pub fn issuing_node(mut self, node_id: &str) -> Self {
        self.claims = self.claims.issuing_node(node_id);
        self
    }

    /// Set checkpoint.
    #[must_use]
    pub fn checkpoint(mut self, id: &[u8], seq: u64) -> Self {
        self.claims = self.claims.checkpoint(id, seq);
        self
    }

    /// Set the issuer.
    #[must_use]
    pub fn issuer(mut self, iss: &str) -> Self {
        self.claims = self.claims.issuer(iss);
        self
    }

    /// Set validity period.
    #[must_use]
    pub fn validity(mut self, not_before: DateTime<Utc>, expires: DateTime<Utc>) -> Self {
        self.claims = self.claims.not_before(not_before).expiration(expires);
        self
    }

    /// Set issued-at to now.
    #[must_use]
    pub fn issued_now(mut self) -> Self {
        self.claims = self.claims.issued_at(Utc::now());
        self
    }

    /// Build and sign the token.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(self, signing_key: &Ed25519SigningKey) -> CryptoResult<CoseToken> {
        CoseToken::sign(signing_key, &self.claims)
    }
}

impl Default for CapabilityTokenBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn cwt_claims_cbor_roundtrip() {
        let claims = CwtClaims::new()
            .issuer("test-issuer")
            .subject("test-subject")
            .capability_id("cap:test.read");

        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();

        assert_eq!(parsed.get_issuer(), Some("test-issuer"));
        assert_eq!(parsed.get_subject(), Some("test-subject"));
        assert_eq!(parsed.get_capability_id(), Some("cap:test.read"));
    }

    #[test]
    fn cose_token_sign_verify() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();

        let claims = CwtClaims::new()
            .issuer("test")
            .capability_id("cap:test.read")
            .zone_id("z:work");

        let token = CoseToken::sign(&sk, &claims).unwrap();
        let verified_claims = token.verify(&pk).unwrap();

        assert_eq!(verified_claims.get_issuer(), Some("test"));
        assert_eq!(verified_claims.get_capability_id(), Some("cap:test.read"));
        assert_eq!(verified_claims.get_zone_id(), Some("z:work"));
    }

    #[test]
    fn cose_token_wrong_key_fails() {
        let sk1 = Ed25519SigningKey::generate();
        let sk2 = Ed25519SigningKey::generate();
        let pk2 = sk2.verifying_key();

        let claims = CwtClaims::new().issuer("test");
        let token = CoseToken::sign(&sk1, &claims).unwrap();

        assert!(token.verify(&pk2).is_err());
    }

    #[test]
    fn cose_token_cbor_roundtrip() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();

        let claims = CwtClaims::new().issuer("test").capability_id("cap:test");
        let token = CoseToken::sign(&sk, &claims).unwrap();

        let cbor = token.to_cbor().unwrap();
        let parsed = CoseToken::from_cbor(&cbor).unwrap();
        let verified = parsed.verify(&pk).unwrap();

        assert_eq!(verified.get_issuer(), Some("test"));
    }

    #[test]
    fn cose_token_key_id() {
        let sk = Ed25519SigningKey::generate();
        let claims = CwtClaims::new().issuer("test");
        let token = CoseToken::sign(&sk, &claims).unwrap();

        let kid_bytes = token.get_key_id().unwrap();
        assert_eq!(kid_bytes.len(), 8);
        assert_eq!(kid_bytes, sk.key_id().as_bytes());
    }

    #[test]
    fn cose_token_verify_with_lookup() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let kid = sk.key_id();

        let claims = CwtClaims::new().issuer("test");
        let token = CoseToken::sign(&sk, &claims).unwrap();

        let verified = token
            .verify_with_lookup(|k| if k == &kid { Some(pk) } else { None })
            .unwrap();

        assert_eq!(verified.get_issuer(), Some("test"));
    }

    #[test]
    fn token_timing_validation() {
        let now = Utc::now();
        let past = now - Duration::hours(1);
        let future = now + Duration::hours(1);

        // Valid token
        let valid_claims = CwtClaims::new().not_before(past).expiration(future);
        assert!(CoseToken::validate_timing(&valid_claims, now).is_ok());

        // Expired token
        let expired_claims = CwtClaims::new().expiration(past);
        assert!(matches!(
            CoseToken::validate_timing(&expired_claims, now),
            Err(CryptoError::TokenExpired)
        ));

        // Not yet valid
        let future_claims = CwtClaims::new().not_before(future);
        assert!(matches!(
            CoseToken::validate_timing(&future_claims, now),
            Err(CryptoError::TokenNotYetValid)
        ));
    }

    #[test]
    fn capability_token_builder() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();

        let now = Utc::now();
        let expires = now + Duration::hours(24);

        let token = CapabilityTokenBuilder::new()
            .capability_id("cap:discord.send")
            .zone_id("z:work")
            .principal("agent:claude")
            .operations(&["discord.send_message", "discord.read_messages"])
            .issuer("node:primary")
            .validity(now, expires)
            .issued_now()
            .sign(&sk)
            .unwrap();

        let claims = token.verify(&pk).unwrap();
        assert_eq!(claims.get_capability_id(), Some("cap:discord.send"));
        assert_eq!(claims.get_zone_id(), Some("z:work"));

        CoseToken::validate_timing(&claims, now).unwrap();
    }

    #[test]
    fn claims_deterministic_encoding() {
        // Same claims should produce same CBOR
        let claims1 = CwtClaims::new()
            .issuer("test")
            .subject("sub")
            .capability_id("cap");

        let claims2 = CwtClaims::new()
            .capability_id("cap")
            .issuer("test")
            .subject("sub");

        // BTreeMap ensures deterministic order regardless of insertion order
        assert_eq!(claims1.to_cbor().unwrap(), claims2.to_cbor().unwrap());
    }
}
