//! MeshNode orchestration glue for FCP2.
//!
//! This module ties together admission control, gossip, symbol requests,
//! degraded-mode control-plane transport, and execution planning into a
//! single cohesive node interface.
//!
//! The goal is to provide a safe, explicit surface for MeshNode behavior
//! without embedding transport specifics.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use fcp_core::{
    CapabilityVerifier, FcpError, InvokeRequest, InvokeValidationError, ObjectId, OperationIntent,
    OperationReceipt, RevocationRegistry, TailscaleNodeId, ZoneId,
};
use fcp_crypto::{CwtClaims, Ed25519Signature, Ed25519VerifyingKey};
use fcp_protocol::{DecodeStatus, SymbolAck, SymbolRequest};
use fcp_raptorq::RaptorQConfig;
use fcp_store::{ObjectStore, QuarantineStore, SymbolStore};
use fcp_tailscale::NodeId;
use thiserror::Error;
use tracing::debug;

use crate::admission::{
    AdmissionController, AdmissionError, AdmissionPolicy, ObjectAdmissionClass,
};
use crate::degraded::{
    ControlPlaneEnvelope, ControlPlaneHandler, DegradedModeDecoder, DegradedModeEncoder,
    DegradedTransportError, RetentionClass,
};
use crate::device::DeviceProfile;
use crate::gossip::{GossipConfig, MeshGossip};
use crate::planner::{
    CandidateNode, ExecutionPlanner, HeldLease, NodeInfo, PlannerContext, PlannerInput,
};
use crate::session::MeshSession;
use crate::symbol_request::{
    SymbolRequestError, SymbolRequestHandler, SymbolRequestMetrics, SymbolRequestPolicy,
    SymbolResponse, SymbolResponseBuilder, TargetedRepairEngine,
};

/// MeshNode configuration (builder-style).
#[derive(Debug, Clone)]
pub struct MeshNodeConfig {
    /// Local node ID (Tailscale).
    pub node_id: String,
    /// Admission control policy.
    pub admission_policy: AdmissionPolicy,
    /// Gossip configuration.
    pub gossip_config: GossipConfig,
    /// Symbol request policy.
    pub symbol_request_policy: SymbolRequestPolicy,
    /// RaptorQ configuration for degraded control-plane transport.
    pub raptorq_config: RaptorQConfig,
    /// Sender instance ID for degraded-mode frames (reboot-safety).
    pub sender_instance_id: u64,
}

impl MeshNodeConfig {
    /// Create a new config with defaults and a node ID.
    #[must_use]
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            admission_policy: AdmissionPolicy::default(),
            gossip_config: GossipConfig::default(),
            symbol_request_policy: SymbolRequestPolicy::default(),
            raptorq_config: RaptorQConfig::default(),
            sender_instance_id: rand::random::<u64>(),
        }
    }

    /// Override admission policy.
    #[must_use]
    pub fn with_admission_policy(mut self, policy: AdmissionPolicy) -> Self {
        self.admission_policy = policy;
        self
    }

    /// Override gossip configuration.
    #[must_use]
    pub fn with_gossip_config(mut self, config: GossipConfig) -> Self {
        self.gossip_config = config;
        self
    }

    /// Override symbol request policy.
    #[must_use]
    pub fn with_symbol_request_policy(mut self, policy: SymbolRequestPolicy) -> Self {
        self.symbol_request_policy = policy;
        self
    }

    /// Override RaptorQ configuration.
    #[must_use]
    pub fn with_raptorq_config(mut self, config: RaptorQConfig) -> Self {
        self.raptorq_config = config;
        self
    }

    /// Override sender instance ID.
    #[must_use]
    pub const fn with_sender_instance_id(mut self, sender_instance_id: u64) -> Self {
        self.sender_instance_id = sender_instance_id;
        self
    }
}

/// MeshNode errors for orchestration surfaces.
#[derive(Debug, Error)]
pub enum MeshNodeError {
    /// Admission control rejected a request.
    #[error("admission rejected: {0}")]
    Admission(#[from] AdmissionError),

    /// Symbol request handling error.
    #[error("symbol request error: {0}")]
    SymbolRequest(#[from] SymbolRequestError),

    /// Object store error.
    #[error("object store error: {0}")]
    ObjectStore(#[from] fcp_store::ObjectStoreError),

    /// Symbol store error.
    #[error("symbol store error: {0}")]
    SymbolStore(#[from] fcp_store::SymbolStoreError),

    /// Quarantine error.
    #[error("quarantine error: {0}")]
    Quarantine(#[from] fcp_store::QuarantineError),

    /// Degraded-mode transport error.
    #[error("degraded transport error: {0}")]
    DegradedTransport(#[from] DegradedTransportError),

    /// Enforcement error.
    #[error("enforcement error: {0}")]
    Enforcement(#[from] MeshNodeEnforcementError),
}

/// Enforcement errors for control-plane requests.
#[derive(Debug, Error)]
pub enum MeshNodeEnforcementError {
    /// Invoke request validation error.
    #[error("invoke validation error: {0}")]
    InvokeValidation(#[from] InvokeValidationError),

    /// Capability token verification failed.
    #[error("capability verification failed: {0}")]
    CapabilityVerification(#[from] FcpError),

    /// Holder proof required for holder-bound token.
    #[error("holder proof required for holder node {holder_node}")]
    HolderProofRequired { holder_node: String },

    /// Holder proof node mismatch.
    #[error("holder proof node mismatch: expected {expected}, got {actual}")]
    HolderProofNodeMismatch { expected: String, actual: String },

    /// Holder proof verification failed.
    #[error("holder proof verification failed")]
    HolderProofInvalid,

    /// Holder proof key missing.
    #[error("holder proof key missing for holder node {holder_node}")]
    HolderKeyMissing { holder_node: String },

    /// Capability token missing JTI claim.
    #[error("capability token missing jti claim")]
    MissingTokenJti,

    /// Capability token revoked.
    #[error("capability token revoked: {token_id}")]
    TokenRevoked { token_id: ObjectId },

    /// Receipt validation error.
    #[error("receipt validation failed: {0}")]
    ReceiptValidation(#[from] fcp_core::OperationValidationError),
}

/// Per-peer state used for planning.
#[derive(Debug, Clone)]
pub struct PeerState {
    /// Device profile.
    pub profile: DeviceProfile,
    /// Symbols present on peer.
    pub local_symbols: HashSet<ObjectId>,
    /// Leases held by peer.
    pub held_leases: Vec<HeldLease>,
    /// Last observed timestamp (ms since epoch).
    pub last_seen_ms: u64,
}

/// MeshNode metrics (coarse-grained).
#[derive(Debug, Default, Clone)]
pub struct MeshNodeMetrics {
    /// Symbol request metrics.
    pub symbol_requests: SymbolRequestMetrics,
    /// Gossip announcements emitted.
    pub gossip_announcements: u64,
    /// Gossip summaries processed.
    pub gossip_updates: u64,
    /// Peer updates applied.
    pub peer_updates: u64,
}

/// MeshNode orchestration entrypoint.
pub struct MeshNode {
    local_node: NodeId,
    local_node_ts: TailscaleNodeId,
    admission: AdmissionController,
    gossip: MeshGossip,
    symbol_requests: SymbolRequestHandler,
    symbol_metrics: SymbolRequestMetrics,
    planner: ExecutionPlanner,
    degraded_encoder: DegradedModeEncoder,
    degraded_decoder: DegradedModeDecoder,
    object_store: Arc<dyn ObjectStore>,
    symbol_store: Arc<dyn SymbolStore>,
    quarantine_store: Arc<QuarantineStore>,
    sessions: HashMap<NodeId, MeshSession>,
    peers: HashMap<NodeId, PeerState>,
    local_profile: Option<DeviceProfile>,
    local_symbols: HashSet<ObjectId>,
    local_leases: Vec<HeldLease>,
    sent_symbols: HashMap<ObjectId, HashSet<u32>>,
    metrics: MeshNodeMetrics,
}

impl MeshNode {
    /// Create a new MeshNode with explicit stores.
    #[must_use]
    pub fn new(
        config: MeshNodeConfig,
        object_store: Arc<dyn ObjectStore>,
        symbol_store: Arc<dyn SymbolStore>,
        quarantine_store: Arc<QuarantineStore>,
    ) -> Self {
        let local_node = NodeId::new(config.node_id.clone());
        let local_node_ts = TailscaleNodeId::new(config.node_id.clone());

        Self {
            admission: AdmissionController::new(config.admission_policy),
            gossip: MeshGossip::new(local_node_ts.clone(), config.gossip_config),
            symbol_requests: SymbolRequestHandler::new(config.symbol_request_policy),
            symbol_metrics: SymbolRequestMetrics::default(),
            planner: ExecutionPlanner::new(),
            degraded_encoder: DegradedModeEncoder::new(
                config.raptorq_config.clone(),
                config.sender_instance_id,
            ),
            degraded_decoder: DegradedModeDecoder::new(config.raptorq_config),
            object_store,
            symbol_store,
            quarantine_store,
            sessions: HashMap::new(),
            local_node,
            local_node_ts,
            peers: HashMap::new(),
            local_profile: None,
            local_symbols: HashSet::new(),
            local_leases: Vec::new(),
            sent_symbols: HashMap::new(),
            metrics: MeshNodeMetrics::default(),
        }
    }

    /// Local node ID (planner/admission).
    #[must_use]
    pub const fn local_node_id(&self) -> &NodeId {
        &self.local_node
    }

    /// Local node ID (gossip/FCPS).
    #[must_use]
    pub const fn local_tailscale_id(&self) -> &TailscaleNodeId {
        &self.local_node_ts
    }

    /// Update local device profile and symbol/lease state.
    pub fn update_local_state(
        &mut self,
        profile: DeviceProfile,
        local_symbols: HashSet<ObjectId>,
        held_leases: Vec<HeldLease>,
    ) {
        self.local_profile = Some(profile);
        self.local_symbols = local_symbols;
        self.local_leases = held_leases;
    }

    /// Update or insert peer state.
    pub fn update_peer_state(
        &mut self,
        node_id: NodeId,
        profile: DeviceProfile,
        local_symbols: HashSet<ObjectId>,
        held_leases: Vec<HeldLease>,
        now_ms: u64,
    ) {
        let state = PeerState {
            profile,
            local_symbols,
            held_leases,
            last_seen_ms: now_ms,
        };
        self.peers.insert(node_id, state);
        self.metrics.peer_updates += 1;
    }

    /// Remove a peer from tracking.
    pub fn remove_peer(&mut self, node_id: &NodeId) {
        self.peers.remove(node_id);
    }

    /// Current peer count (excluding local).
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Register an authenticated mesh session for a peer.
    pub fn register_session(&mut self, session: MeshSession, now_ms: u64) {
        self.admission
            .set_authenticated(&session.peer_id, true, now_ms);
        self.sessions.insert(session.peer_id.clone(), session);
    }

    /// Remove a mesh session for a peer (marks unauthenticated).
    pub fn remove_session(&mut self, peer_id: &NodeId, now_ms: u64) {
        self.sessions.remove(peer_id);
        self.admission.set_authenticated(peer_id, false, now_ms);
    }

    /// Check whether a peer is authenticated.
    #[must_use]
    pub fn is_peer_authenticated(&self, peer_id: &NodeId) -> bool {
        self.sessions.contains_key(peer_id) || self.admission.is_authenticated(peer_id)
    }

    /// Build a planner input from current local + peer state.
    fn build_planner_input(&self, now_ms: u64) -> PlannerInput {
        let mut nodes = Vec::new();
        let mut singleton_holder: Option<String> = None;
        let now_secs = now_ms / 1000;

        if let Some(profile) = &self.local_profile {
            if singleton_holder.is_none()
                && self.local_leases.iter().any(|lease| {
                    lease.purpose == crate::planner::LeasePurpose::SingletonWriter
                        && lease.expires_at > now_secs
                })
            {
                singleton_holder = Some(profile.node_id.as_str().to_string());
            }

            nodes.push(NodeInfo {
                profile: profile.clone(),
                local_symbols: self.local_symbols.clone(),
                held_leases: self.local_leases.clone(),
            });
        }

        for state in self.peers.values() {
            if singleton_holder.is_none()
                && state.held_leases.iter().any(|lease| {
                    lease.purpose == crate::planner::LeasePurpose::SingletonWriter
                        && lease.expires_at > now_secs
                })
            {
                singleton_holder = Some(state.profile.node_id.as_str().to_string());
            }

            nodes.push(NodeInfo {
                profile: state.profile.clone(),
                local_symbols: state.local_symbols.clone(),
                held_leases: state.held_leases.clone(),
            });
        }

        let mut input = PlannerInput::new(nodes, now_ms);
        if let Some(holder) = singleton_holder {
            input = input.with_singleton_holder(holder);
        }
        input
    }

    /// Plan execution candidates for a connector.
    #[must_use]
    pub fn plan_execution(&self, context: &PlannerContext, now_ms: u64) -> Vec<CandidateNode> {
        let input = self.build_planner_input(now_ms);
        self.planner.plan(&input, context)
    }

    /// Enforce capability, holder proof, and revocation checks for an invoke request.
    ///
    /// Returns the verified capability claims on success.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeEnforcementError` if idempotency validation, capability
    /// verification, holder proof checks, or revocation checks fail.
    pub fn enforce_invoke_request<F>(
        &self,
        request: &InvokeRequest,
        verifier: &CapabilityVerifier,
        revocations: &RevocationRegistry,
        resource_uris: &[String],
        mut holder_key_lookup: F,
    ) -> Result<CwtClaims, MeshNodeEnforcementError>
    where
        F: FnMut(&TailscaleNodeId) -> Option<Ed25519VerifyingKey>,
    {
        request.validate_idempotency_key()?;

        let claims =
            verifier.verify(&request.capability_token, &request.operation, resource_uris)?;

        if let Some(holder_node) = claims.get_holder_node() {
            let proof = request.holder_proof.as_ref().ok_or_else(|| {
                MeshNodeEnforcementError::HolderProofRequired {
                    holder_node: holder_node.to_string(),
                }
            })?;

            if proof.holder_node.as_str() != holder_node {
                return Err(MeshNodeEnforcementError::HolderProofNodeMismatch {
                    expected: holder_node.to_string(),
                    actual: proof.holder_node.as_str().to_string(),
                });
            }

            let token_jti = claims
                .get_jti()
                .ok_or(MeshNodeEnforcementError::MissingTokenJti)?;
            let signable =
                fcp_core::HolderProof::signable_bytes(&request.id, &request.operation, token_jti);

            let key = holder_key_lookup(&proof.holder_node).ok_or_else(|| {
                MeshNodeEnforcementError::HolderKeyMissing {
                    holder_node: proof.holder_node.as_str().to_string(),
                }
            })?;

            let signature = Ed25519Signature::from_bytes(&proof.signature);
            if key.verify(&signable, &signature).is_err() {
                return Err(MeshNodeEnforcementError::HolderProofInvalid);
            }
        }

        let token_jti = claims
            .get_jti()
            .ok_or(MeshNodeEnforcementError::MissingTokenJti)?;
        let token_id = ObjectId::from_unscoped_bytes(token_jti);
        if revocations.is_revoked(&token_id) {
            return Err(MeshNodeEnforcementError::TokenRevoked { token_id });
        }

        Ok(claims)
    }

    /// Validate that a receipt correctly references its intent.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeEnforcementError::ReceiptValidation` if binding fails.
    pub fn validate_receipt_binding(
        &self,
        receipt: &OperationReceipt,
        intent: &OperationIntent,
    ) -> Result<(), MeshNodeEnforcementError> {
        fcp_core::validate_receipt_intent_binding(receipt, intent)?;
        Ok(())
    }

    /// Announce an admitted object for gossip.
    pub fn announce_object(
        &mut self,
        zone_id: &ZoneId,
        object_id: &ObjectId,
        admission: ObjectAdmissionClass,
        now_ms: u64,
    ) -> bool {
        let added = self
            .gossip
            .announce_object(zone_id, object_id, admission, now_ms / 1000);
        if added {
            self.metrics.gossip_announcements += 1;
        }
        added
    }

    /// Announce a symbol for gossip (admitted objects only).
    pub fn announce_symbol(
        &mut self,
        zone_id: &ZoneId,
        object_id: &ObjectId,
        esi: u32,
        admission: ObjectAdmissionClass,
        now_ms: u64,
    ) -> bool {
        let added = self
            .gossip
            .announce_symbol(zone_id, object_id, esi, admission, now_ms / 1000);
        if added {
            self.metrics.gossip_announcements += 1;
        }
        added
    }

    /// Handle a symbol request using admission control and targeted repair.
    ///
    /// # Errors
    /// Returns `SymbolRequestError` on validation or store failures.
    pub async fn handle_symbol_request(
        &mut self,
        request: SymbolRequest,
        peer: &NodeId,
        is_authenticated: bool,
        now_ms: u64,
    ) -> Result<SymbolResponse, SymbolRequestError> {
        if self.symbol_requests.should_stop(&request.object_id) {
            return Err(SymbolRequestError::AlreadyComplete {
                object_id: request.object_id.to_string(),
            });
        }

        if self.quarantine_store.contains(&request.object_id) {
            return Err(SymbolRequestError::AdmissionRejected(
                AdmissionError::ObjectQuarantined {
                    object_id: request.object_id.to_string(),
                },
            ));
        }

        let authenticated = is_authenticated || self.is_peer_authenticated(peer);
        self.admission
            .set_authenticated(peer, authenticated, now_ms);

        let validated = match self.symbol_requests.validate_request(
            &request,
            authenticated,
            &mut self.admission,
            peer,
            now_ms,
        ) {
            Ok(validated) => {
                self.symbol_metrics.record_validated();
                validated
            }
            Err(SymbolRequestError::BoundsExceeded {
                requested,
                max_allowed,
            }) => {
                self.symbol_metrics.record_bounds_rejection();
                return Err(SymbolRequestError::BoundsExceeded {
                    requested,
                    max_allowed,
                });
            }
            Err(SymbolRequestError::AdmissionRejected(err)) => {
                self.symbol_metrics.record_admission_rejection();
                return Err(SymbolRequestError::AdmissionRejected(err));
            }
            Err(err) => return Err(err),
        };

        let meta = self
            .symbol_store
            .get_object_meta(&request.object_id)
            .await
            .map_err(|err| match err {
                fcp_store::SymbolStoreError::ObjectNotFound(_) => {
                    SymbolRequestError::ObjectNotFound {
                        object_id: request.object_id.to_string(),
                    }
                }
                other => SymbolRequestError::InvalidRequest {
                    reason: format!("symbol store error: {other}"),
                },
            })?;

        let symbols = self.symbol_store.get_all_symbols(&request.object_id).await;
        let mut available = HashSet::new();
        for symbol in symbols {
            available.insert(symbol.meta.esi);
        }

        if available.is_empty() {
            return Err(SymbolRequestError::ObjectNotFound {
                object_id: request.object_id.to_string(),
            });
        }

        let mut engine = TargetedRepairEngine::new();
        engine.register_available(request.object_id, available.iter().copied());

        let already_sent = self
            .sent_symbols
            .entry(request.object_id)
            .or_insert_with(HashSet::new);

        let builder = SymbolResponseBuilder::new(
            request.object_id,
            meta.zone_id.clone(),
            request.zone_key_id,
            validated.max_response_symbols,
        );

        let response = builder
            .add_from_repair_engine(&engine, &validated, already_sent)
            .build(available.len() as u32);

        debug!(
            object_id = %response.object_id,
            symbols = response.symbol_esis.len(),
            was_bounded = response.was_bounded,
            "symbol request response prepared"
        );

        already_sent.extend(response.symbol_esis.iter().copied());
        self.symbol_requests
            .track_transfer(&request, response.symbol_esis.iter().copied());
        self.symbol_metrics
            .record_symbols_sent(response.symbol_count(), request.missing_hint.is_some());

        Ok(response)
    }

    /// Apply a decode status update (targeted repair feedback).
    pub fn handle_decode_status(&mut self, status: &DecodeStatus) {
        self.symbol_requests.process_decode_status(status);
    }

    /// Apply a SymbolAck and stop further sends.
    pub fn handle_symbol_ack(&mut self, ack: &SymbolAck) {
        self.symbol_requests.process_symbol_ack(ack);
        self.symbol_metrics.record_ack();
        self.sent_symbols.remove(&ack.object_id);
    }

    /// Encode a control-plane envelope for degraded transport.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError::DegradedTransport` if encoding fails.
    pub fn encode_control_plane(
        &mut self,
        envelope: &ControlPlaneEnvelope,
        epoch_id: u64,
    ) -> Result<Vec<fcp_protocol::FcpsFrame>, MeshNodeError> {
        Ok(self.degraded_encoder.encode(envelope, epoch_id)?)
    }

    /// Decode a control-plane frame in degraded mode.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError::DegradedTransport` if decoding fails.
    pub fn decode_control_plane(
        &mut self,
        frame: &fcp_protocol::FcpsFrame,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
    ) -> Result<Option<ControlPlaneEnvelope>, MeshNodeError> {
        Ok(self
            .degraded_decoder
            .process_frame(frame, expected_zone_id, retention)?)
    }

    /// Decode a control-plane frame and enforce retention via handler.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError` if decoding fails or the handler rejects the
    /// envelope.
    pub fn process_control_plane_frame(
        &mut self,
        frame: &fcp_protocol::FcpsFrame,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
        handler: &dyn ControlPlaneHandler,
    ) -> Result<Option<ControlPlaneEnvelope>, MeshNodeError> {
        let envelope = self.decode_control_plane(frame, expected_zone_id, retention)?;
        if let Some(ref env) = envelope {
            handler.handle(env.clone())?;
        }
        Ok(envelope)
    }

    /// Snapshot metrics.
    #[must_use]
    pub fn metrics(&self) -> MeshNodeMetrics {
        let mut metrics = self.metrics.clone();
        metrics.symbol_requests = self.symbol_metrics.clone();
        metrics
    }

    /// Access underlying gossip state (mutable).
    pub fn gossip_mut(&mut self) -> &mut MeshGossip {
        &mut self.gossip
    }

    /// Access admission controller (mutable).
    pub fn admission_mut(&mut self) -> &mut AdmissionController {
        &mut self.admission
    }

    /// Access object store.
    #[must_use]
    pub fn object_store(&self) -> &Arc<dyn ObjectStore> {
        &self.object_store
    }

    /// Access symbol store.
    #[must_use]
    pub fn symbol_store(&self) -> &Arc<dyn SymbolStore> {
        &self.symbol_store
    }

    /// Access quarantine store.
    #[must_use]
    pub fn quarantine_store(&self) -> &Arc<QuarantineStore> {
        &self.quarantine_store
    }
}
