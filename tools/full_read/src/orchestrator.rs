/// Execution Governance Orchestrator
///
/// Orchestrates:
/// 1. Loading a capsule descriptor
/// 2. Verifying integrity via Aether
/// 3. Starting the capsule in sandbox (placeholder)
/// 4. Handling runtime access requests (network, filesystem, resources)
///
/// The orchestrator is stateful; it tracks running instances and their access patterns.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::capsule::{Capsule, IntegrityStatus};
use crate::egl_policy::{AccessRequest, Decision, PolicyContext};
use crate::network_guard::{check_network_access, NetworkAccessRequest, NetworkGuard};

/// Unique identifier for a running capsule instance.
pub type InstanceId = String;

/// Represents a running capsule instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningInstance {
    /// Unique instance ID (e.g., "chrome_pid_1234").
    pub instance_id: InstanceId,
    /// Reference to the capsule descriptor.
    pub capsule_id: String,
    /// Process ID (placeholder; actual PID management is in the sandbox).
    pub pid: u32,
    /// Timestamp when the instance was started.
    pub start_time: u64,
    /// Current integrity status of the executable.
    pub integrity_status: IntegrityStatus,
}

impl RunningInstance {
    /// Creates a new running instance.
    pub fn new(
        instance_id: InstanceId,
        capsule_id: String,
        pid: u32,
        integrity_status: IntegrityStatus,
    ) -> Self {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            instance_id,
            capsule_id,
            pid,
            start_time,
            integrity_status,
        }
    }
}

/// Error types for execution governance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecError {
    /// Capsule binary not found.
    BinaryNotFound(String),
    /// Integrity verification failed.
    IntegrityFailed(String),
    /// Integrity check could not complete.
    VerificationFailed(String),
    /// Sandbox initialization failed.
    SandboxError(String),
    /// Capsule is not running.
    NotRunning(String),
    /// Access request denied by policy.
    AccessDenied(String),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::BinaryNotFound(msg) => write!(f, "BinaryNotFound: {}", msg),
            ExecError::IntegrityFailed(msg) => write!(f, "IntegrityFailed: {}", msg),
            ExecError::VerificationFailed(msg) => write!(f, "VerificationFailed: {}", msg),
            ExecError::SandboxError(msg) => write!(f, "SandboxError: {}", msg),
            ExecError::NotRunning(msg) => write!(f, "NotRunning: {}", msg),
            ExecError::AccessDenied(msg) => write!(f, "AccessDenied: {}", msg),
        }
    }
}

impl std::error::Error for ExecError {}

/// Mock Aether client for integrity verification.
/// In production, this would connect to the actual Aether system.
pub trait AetherClient {
    /// Verifies the integrity of a binary at the given path.
    /// Returns the expected status (Clean, Missing, Tampered, etc.).
    fn verify_binary(&self, path: &str) -> IntegrityStatus;
}

/// Simple mock implementation for testing.
pub struct MockAetherClient {
    /// Map of paths to their integrity status.
    pub known_hashes: HashMap<String, IntegrityStatus>,
}

impl MockAetherClient {
    pub fn new() -> Self {
        Self {
            known_hashes: HashMap::new(),
        }
    }

    pub fn add_binary(&mut self, path: String, status: IntegrityStatus) {
        self.known_hashes.insert(path, status);
    }
}

impl Default for MockAetherClient {
    fn default() -> Self {
        Self::new()
    }
}

impl AetherClient for MockAetherClient {
    fn verify_binary(&self, path: &str) -> IntegrityStatus {
        self.known_hashes
            .get(path)
            .copied()
            .unwrap_or(IntegrityStatus::VerificationFailed)
    }
}

/// Execution context holding policy, network guard, Aether client, and running instances.
pub struct ExecContext {
    /// Policy context for access control.
    pub policy: PolicyContext,
    /// Network guard for network access control.
    pub network_guard: NetworkGuard,
    /// Aether client for integrity verification.
    pub aether: Box<dyn AetherClient>,
    /// Running instances, keyed by instance ID.
    pub running_instances: HashMap<InstanceId, RunningInstance>,
}

impl ExecContext {
    /// Creates a new execution context.
    pub fn new(
        policy: PolicyContext,
        network_guard: NetworkGuard,
        aether: Box<dyn AetherClient>,
    ) -> Self {
        Self {
            policy,
            network_guard,
            aether,
            running_instances: HashMap::new(),
        }
    }

    /// Starts a capsule: verifies integrity and (simulates) launching in sandbox.
    pub fn start_capsule(&mut self, capsule: &Capsule) -> Result<RunningInstance, ExecError> {
        // Check if binary exists (placeholder)
        let binary_path = capsule.binary_path().to_string_lossy();
        if !std::path::Path::new(binary_path.as_ref()).exists() {
            return Err(ExecError::BinaryNotFound(binary_path.to_string()));
        }

        // Verify integrity via Aether
        let integrity_status = self.aether.verify_binary(&binary_path);
        match integrity_status {
            IntegrityStatus::Clean => {
                // OK, proceed
            }
            IntegrityStatus::Tampered => {
                return Err(ExecError::IntegrityFailed(format!(
                    "Binary {} has been tampered with",
                    binary_path
                )));
            }
            IntegrityStatus::Missing => {
                return Err(ExecError::BinaryNotFound(format!(
                    "Binary {} not found",
                    binary_path
                )));
            }
            IntegrityStatus::VerificationFailed => {
                return Err(ExecError::VerificationFailed(format!(
                    "Cannot verify integrity of {}",
                    binary_path
                )));
            }
        }

        // Create a running instance (PID is placeholder)
        let instance_id = format!("{}_{}", capsule.id(), std::process::id());
        let instance = RunningInstance::new(
            instance_id.clone(),
            capsule.id().to_string(),
            12345, // Placeholder PID
            integrity_status,
        );

        // Register the instance
        self.running_instances
            .insert(instance_id, instance.clone());

        Ok(instance)
    }

    /// Handles a network access request from a running instance.
    pub fn handle_network_request(
        &mut self,
        instance_id: &InstanceId,
        request: &NetworkAccessRequest,
    ) -> Result<(), ExecError> {
        // Verify instance is running
        if !self.running_instances.contains_key(instance_id) {
            return Err(ExecError::NotRunning(format!(
                "Instance {} not running",
                instance_id
            )));
        }

        // Evaluate network request
        let decision = check_network_access(request, &self.network_guard, &self.policy);

        match decision {
            Decision::Allow | Decision::Restricted => {
                // Log metadata (timestamp, capsule_id, decision) – no payload/URL details
                // In production, this would write to audit log
                Ok(())
            }
            Decision::Deny => Err(ExecError::AccessDenied(format!(
                "Network access denied for {} to {}:{}",
                request.capsule_id, request.destination_host, request.destination_port
            ))),
        }
    }

    /// Handles a filesystem access request from a running instance.
    pub fn handle_filesystem_request(
        &mut self,
        instance_id: &InstanceId,
        path: &str,
        action: &str,
    ) -> Result<(), ExecError> {
        // Verify instance is running
        if !self.running_instances.contains_key(instance_id) {
            return Err(ExecError::NotRunning(format!(
                "Instance {} not running",
                instance_id
            )));
        }

        let instance = &self.running_instances[instance_id];

        // Lookup capsule to check filesystem permissions (placeholder)
        // In real implementation, we'd lookup the capsule and its sandbox config
        let capsule_id = &instance.capsule_id;

        // Create an access request for policy evaluation
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let request = AccessRequest::new(capsule_id.clone(), path.to_string(), action.to_string(), timestamp);

        // Evaluate against policy
        let decision = self.policy.evaluate(&request);

        match decision {
            Decision::Allow | Decision::Restricted => Ok(()),
            Decision::Deny => Err(ExecError::AccessDenied(format!(
                "Filesystem access denied for {} to {} ({})",
                capsule_id, path, action
            ))),
        }
    }

    /// Stops a running instance.
    pub fn stop_instance(&mut self, instance_id: &InstanceId) -> Result<(), ExecError> {
        if self.running_instances.remove(instance_id).is_some() {
            Ok(())
        } else {
            Err(ExecError::NotRunning(format!(
                "Instance {} not running",
                instance_id
            )))
        }
    }

    /// Lists all running instances.
    pub fn list_running_instances(&self) -> Vec<RunningInstance> {
        self.running_instances.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{NetworkConfig, SandboxConfig};
    use crate::egl_policy::{PolicyRule, Decision};

    fn create_test_capsule() -> Capsule {
        let fs_perms = HashMap::new();
        let network_config = NetworkConfig {
            allowed_hosts: vec!["duckduckgo.com".to_string()],
            blocked_hosts: vec!["tracking.example.com".to_string()],
            allowed_protocols: vec!["https".to_string()],
            default_policy: false,
        };
        let sandbox_config = SandboxConfig {
            filesystem: fs_perms,
            network: network_config,
            devices: HashMap::new(),
            env_whitelist: vec![],
        };
        Capsule::new(
            "chrome".to_string(),
            std::path::PathBuf::from("/usr/bin/google-chrome"),
            "sha256:abc123".to_string(),
            sandbox_config,
            "Chrome browser".to_string(),
        )
    }

    #[test]
    fn orchestrator_starts_capsule_with_clean_integrity() {
        let policy = PolicyContext::new(Decision::Deny);
        let network_guard = NetworkGuard::new();
        let mut aether = MockAetherClient::new();
        aether.add_binary(
            "/usr/bin/google-chrome".to_string(),
            IntegrityStatus::Clean,
        );

        let mut ctx = ExecContext::new(policy, network_guard, Box::new(aether));
        let capsule = create_test_capsule();

        let result = ctx.start_capsule(&capsule);
        assert!(result.is_ok());
        assert_eq!(ctx.running_instances.len(), 1);
    }

    #[test]
    fn orchestrator_rejects_tampered_binary() {
        let policy = PolicyContext::new(Decision::Deny);
        let network_guard = NetworkGuard::new();
        let mut aether = MockAetherClient::new();
        aether.add_binary(
            "/usr/bin/google-chrome".to_string(),
            IntegrityStatus::Tampered,
        );

        let mut ctx = ExecContext::new(policy, network_guard, Box::new(aether));
        let capsule = create_test_capsule();

        let result = ctx.start_capsule(&capsule);
        assert!(result.is_err());
        assert_eq!(ctx.running_instances.len(), 0);
    }

    #[test]
    fn orchestrator_allows_whitelisted_network_access() {
        let mut policy = PolicyContext::new(Decision::Deny);
        policy.add_rule(PolicyRule::new(
            "chrome".to_string(),
            "duckduckgo.com:443".to_string(),
            "connect_https".to_string(),
            Decision::Allow,
            100,
        ));

        let mut network_guard = NetworkGuard::new();
        network_guard.add_trusted_host("duckduckgo.com");

        let mut aether = MockAetherClient::new();
        aether.add_binary(
            "/usr/bin/google-chrome".to_string(),
            IntegrityStatus::Clean,
        );

        let mut ctx = ExecContext::new(policy, network_guard, Box::new(aether));
        let capsule = create_test_capsule();
        let instance = ctx.start_capsule(&capsule).unwrap();

        let net_request = NetworkAccessRequest::new(
            "chrome".to_string(),
            "duckduckgo.com".to_string(),
            443,
            "https".to_string(),
        );

        let result = ctx.handle_network_request(&instance.instance_id, &net_request);
        assert!(result.is_ok());
    }

    #[test]
    fn orchestrator_blocks_tracking_domain_access() {
        let policy = PolicyContext::new(Decision::Deny);
        let network_guard = NetworkGuard::new();

        let mut aether = MockAetherClient::new();
        aether.add_binary(
            "/usr/bin/google-chrome".to_string(),
            IntegrityStatus::Clean,
        );

        let mut ctx = ExecContext::new(policy, network_guard, Box::new(aether));
        let capsule = create_test_capsule();
        let instance = ctx.start_capsule(&capsule).unwrap();

        let net_request = NetworkAccessRequest::new(
            "chrome".to_string(),
            "tracking.example.com".to_string(),
            443,
            "https".to_string(),
        );

        let result = ctx.handle_network_request(&instance.instance_id, &net_request);
        assert!(result.is_err());
    }

    #[test]
    fn orchestrator_manages_instance_lifecycle() {
        let policy = PolicyContext::new(Decision::Deny);
        let network_guard = NetworkGuard::new();
        let mut aether = MockAetherClient::new();
        aether.add_binary(
            "/usr/bin/google-chrome".to_string(),
            IntegrityStatus::Clean,
        );

        let mut ctx = ExecContext::new(policy, network_guard, Box::new(aether));
        let capsule = create_test_capsule();
        let instance = ctx.start_capsule(&capsule).unwrap();

        assert_eq!(ctx.list_running_instances().len(), 1);

        let stop_result = ctx.stop_instance(&instance.instance_id);
        assert!(stop_result.is_ok());
        assert_eq!(ctx.list_running_instances().len(), 0);
    }
}
