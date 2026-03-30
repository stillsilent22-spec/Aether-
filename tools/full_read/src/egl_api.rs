/// Execution Governance Layer (EGL) – Public API
///
/// PRIVACY & SECURITY GUARANTEES:
/// ============================
///
/// This module provides a complete local execution governance system for desktop clients.
/// It ensures that applications run safely and deterministically without compromising privacy.
///
/// Key Principles:
///
/// 1. CONTENT BLINDNESS
///    - The EGL never reads application content, files, or network payloads.
///    - All decisions are made on metadata only (capsule ID, resource type/target, action).
///    - No semantic analysis, no AI/ML, no external profiling.
///
/// 2. LOCAL EXECUTION
///    - All governance happens locally on the device.
///    - No cloud dependencies, no external policy services, no telemetry.
///    - No data leaves the system except as explicitly allowed by policy.
///
/// 3. STRUCTURAL INTEGRITY (via Aether)
///    - Before any capsule is launched, its binary is verified for integrity.
///    - Aether checks the structural/cryptographic hash of the executable.
///    - If the binary has been tampered with, the capsule is NOT launched.
///    - This uses Aether's existing local verification, not cloud-based attestation.
///
/// 4. RULE-BASED GOVERNANCE
///    - Access decisions derive from explicit policy rules, not machine learning.
///    - All decisions are deterministic: same request, same environment = same outcome.
///    - Rules are human-readable and auditable.
///
/// 5. NETWORK ISOLATION & CLEAN CHANNELS
///    - The EGL enforces a whitelist of allowed network destinations.
///    - By default, all network access is denied unless explicitly allowed.
///    - Known telemetry/tracking domains are permanently blacklisted.
///    - All traffic can be routed through privacy-friendly channels (e.g., DuckDuckGo).
///
/// 6. STRICT LOGGING (METADATA ONLY)
///    - Audit logs record only: timestamp, capsule_id, action, decision, resource_type.
///    - These are immutable and stored locally.
///    - NO file paths, NO URLs, NO content hashes, NO personally identifiable data.
///    - Log entries enable forensic analysis without exposing sensitive information.
///
/// 7. SANDBOX INTEGRATION
///    - The EGL coordinates with system sandbox frameworks (currently a trait/interface).
///    - Sandbox restrictions are enforced at the OS level; EGL provides policy guidance.
///    - Sandboxed processes cannot escape the governance layer.
///
/// EXAMPLE WORKFLOW:
/// =================
/// 1. Admin definitions:
///    - Capsule "chrome" has binary /usr/bin/google-chrome
///    - Policy: chrome can connect to duckduckgo.com:443 (https)
///    - Policy: chrome cannot connect to tracking.example.com
///    - Aether hash for /usr/bin/google-chrome is known_good_hash
///
/// 2. User launches chrome:
///    - EGL calls start_capsule("chrome")
///    - Aether verifies /usr/bin/google-chrome matches known_good_hash
///    - If match: sandbox is initialized, capsule runs
///    - If mismatch: capsule is silently blocked; admin/user is notified
///
/// 3. Chrome attempts to connect to duckduckgo.com:
///    - Network guard checks: "https" is allowed protocol? Yes.
///    - Network guard checks: "duckduckgo.com" in tracking domains? No.
///    - Policy evaluates: does "chrome" have "connect_https" to "duckduckgo.com"? Yes.
///    - Decision: Allow.
///    - Audit log: { timestamp, "chrome", "connect", "allow" }
///
/// 4. Chrome attempts to connect to tracking.example.com:
///    - Network guard checks: tracking domain? Yes.
///    - Decision: Deny (no further evaluation needed).
///    - Audit log: { timestamp, "chrome", "connect", "deny" }
///
/// ARCHITECTURE:
/// ==============
/// - capsule.rs: Models execution capsules (binaries + sandbox config).
/// - egl_policy.rs: Rules and deterministic policy evaluation.
/// - network_guard.rs: Network whitelist/blacklist and first-pass validation.
/// - orchestrator.rs: Coordinates capsule loading, verification, and runtime governance.
/// - egl_api.rs (this file): High-level interface for users and admins.
///
/// NO EXTERNAL DEPENDENCIES:
/// - Aether is called only for cryptographic integrity verification (local hash comparison).
/// - DuckDuckGo or other privacy services are optional network destinations, not required.
/// - The EGL does not depend on any online service to function.

use crate::capsule::{Capsule, NetworkConfig, Permission, SandboxConfig};
use crate::egl_policy::{Decision, PolicyContext, PolicyRule};
use crate::network_guard::{NetworkAccessRequest, NetworkGuard};
use crate::orchestrator::{AetherClient, ExecContext, ExecError, InstanceId, MockAetherClient};
use std::collections::HashMap;
use std::path::Path;

/// High-level API for launching and governing applications.
pub struct GoverningLauncher {
    /// The underlying execution context.
    context: ExecContext,
    /// Capsule definitions, keyed by capsule ID.
    capsules: HashMap<String, Capsule>,
}

impl GoverningLauncher {
    /// Creates a new governing launcher with default (safe) settings.
    pub fn new() -> Self {
        let policy = PolicyContext::new(Decision::Deny); // Default: deny everything
        let network_guard = NetworkGuard::new(); // Default: block tracking, allow safe protocols
        let aether = Box::new(MockAetherClient::new()); // Placeholder Aether client

        let context = ExecContext::new(policy, network_guard, aether);

        Self {
            context,
            capsules: HashMap::new(),
        }
    }

    /// Registers a capsule descriptor.
    pub fn register_capsule(&mut self, capsule: Capsule) {
        self.capsules.insert(capsule.id().to_string(), capsule);
    }

    /// Adds a policy rule.
    pub fn add_policy_rule(&mut self, rule: PolicyRule) {
        self.context.policy.add_rule(rule);
    }

    /// Adds a trusted network host.
    pub fn add_trusted_host(&mut self, host: &str) {
        self.context.network_guard.add_trusted_host(host);
    }

    /// Adds a tracking domain to the blacklist.
    pub fn add_tracking_domain(&mut self, domain: &str) {
        self.context.network_guard.add_tracking_domain(domain);
    }

    /// Sets the Aether client (for real verification, not mock).
    pub fn set_aether_client(&mut self, aether: Box<dyn AetherClient>) {
        self.context.aether = aether;
    }

    /// Launches a capsule by ID. Verifies integrity and starts in sandbox.
    pub fn launch_governed_app(&mut self, app_id: &str) -> Result<InstanceId, ExecError> {
        let capsule = self
            .capsules
            .get(app_id)
            .ok_or_else(|| ExecError::BinaryNotFound(format!("Capsule '{}' not registered", app_id)))?
            .clone();

        let instance = self.context.start_capsule(&capsule)?;
        Ok(instance.instance_id)
    }

    /// Handles a network access request from a running instance.
    pub fn handle_network_access(
        &mut self,
        instance_id: &InstanceId,
        destination_host: &str,
        destination_port: u16,
        protocol: &str,
    ) -> Result<(), ExecError> {
        let request = NetworkAccessRequest::new(
            "unknown".to_string(), // Will be filled from instance context if needed
            destination_host.to_string(),
            destination_port,
            protocol.to_string(),
        );

        self.context.handle_network_request(instance_id, &request)
    }

    /// Handles a filesystem access request from a running instance.
    pub fn handle_filesystem_access(
        &mut self,
        instance_id: &InstanceId,
        path: &str,
        action: &str,
    ) -> Result<(), ExecError> {
        self.context.handle_filesystem_request(instance_id, path, action)
    }

    /// Stops a running instance.
    pub fn stop_app(&mut self, instance_id: &InstanceId) -> Result<(), ExecError> {
        self.context.stop_instance(instance_id)
    }

    /// Retrieves the default policy context (for advanced configuration).
    pub fn policy_mut(&mut self) -> &mut PolicyContext {
        &mut self.context.policy
    }

    /// Retrieves the network guard (for advanced configuration).
    pub fn network_guard_mut(&mut self) -> &mut NetworkGuard {
        &mut self.context.network_guard
    }

    /// Lists all registered capsules.
    pub fn list_capsules(&self) -> Vec<String> {
        self.capsules.keys().cloned().collect()
    }

    /// Lists all running instances.
    pub fn list_running(&self) -> Vec<String> {
        self.context
            .list_running_instances()
            .iter()
            .map(|i| i.instance_id.clone())
            .collect()
    }
}

impl Default for GoverningLauncher {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// CONVENIENCE BUILDERS & HELPER FUNCTIONS
// =============================================================================

/// Helper function to create a browser capsule template (e.g., Chrome, Firefox).
pub fn create_browser_capsule(
    id: &str,
    binary_path: &Path,
    expected_hash: &str,
) -> Capsule {
    let mut fs_perms = HashMap::new();
    // Browsers typically need access to download folder and cache
    fs_perms.insert("/tmp".to_string(), Permission::ReadWrite);
    fs_perms.insert(
        "/home/*/Downloads".to_string(),
        Permission::ReadWrite,
    );
    fs_perms.insert("/var/cache".to_string(), Permission::ReadWrite);

    let network_config = NetworkConfig {
        allowed_hosts: vec![
            "duckduckgo.com".to_string(),
            "*.duckduckgo.com".to_string(),
        ],
        blocked_hosts: vec![
            "facebook.com".to_string(),
            "tracking.example.com".to_string(),
            "gstatic.com".to_string(),
        ],
        allowed_protocols: vec!["tcp".to_string(), "tls".to_string()],
        default_policy: false,
    };

    let sandbox_config = SandboxConfig {
        filesystem: fs_perms,
        network: network_config,
        devices: HashMap::new(),
        env_whitelist: vec!["PATH".to_string(), "HOME".to_string(), "LANG".to_string()],
    };

    Capsule::new(
        id.to_string(),
        binary_path.to_path_buf(),
        expected_hash.to_string(),
        sandbox_config,
        format!("{} browser with privacy policy", id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::IntegrityStatus;

    fn setup_launcher() -> GoverningLauncher {
        let mut launcher = GoverningLauncher::new();

        // Register a test capsule
        let mut fs_perms = HashMap::new();
        fs_perms.insert("/tmp".to_string(), Permission::ReadWrite);

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

        let capsule = Capsule::new(
            "test_chrome".to_string(),
            std::path::PathBuf::from("/usr/bin/google-chrome"),
            "sha256:abc123".to_string(),
            sandbox_config,
            "Test Chrome".to_string(),
        );

        launcher.register_capsule(capsule);

        // Set up Aether mock to return Clean for this binary
        let mut aether = MockAetherClient::new();
        aether.add_binary(
            "/usr/bin/google-chrome".to_string(),
            IntegrityStatus::Clean,
        );
        launcher.set_aether_client(Box::new(aether));

        // Add policy rule
        launcher.add_policy_rule(PolicyRule::new(
            "test_chrome".to_string(),
            "duckduckgo.com:443".to_string(),
            "connect_https".to_string(),
            Decision::Allow,
            100,
        ));

        launcher.add_trusted_host("duckduckgo.com");

        launcher
    }

    #[test]
    fn launcher_registers_and_lists_capsules() {
        let launcher = setup_launcher();
        let capsules = launcher.list_capsules();
        assert_eq!(capsules.len(), 1);
        assert!(capsules.contains(&"test_chrome".to_string()));
    }

    #[test]
    fn launcher_launches_capsule_with_clean_integrity() {
        let mut launcher = setup_launcher();
        let result = launcher.launch_governed_app("test_chrome");
        assert!(result.is_ok());
        assert_eq!(launcher.list_running().len(), 1);
    }

    #[test]
    fn launcher_denies_unregistered_capsule() {
        let mut launcher = setup_launcher();
        let result = launcher.launch_governed_app("unknown_app");
        assert!(result.is_err());
    }

    #[test]
    fn launcher_enforces_network_policy() {
        let mut launcher = setup_launcher();
        let instance_id = launcher.launch_governed_app("test_chrome").unwrap();

        // Allowed host
        let allow_result = launcher.handle_network_access(
            &instance_id,
            "duckduckgo.com",
            443,
            "https",
        );
        assert!(allow_result.is_ok());

        // Tracking domain (should be blocked)
        let deny_result = launcher.handle_network_access(
            &instance_id,
            "tracking.example.com",
            443,
            "https",
        );
        assert!(deny_result.is_err());
    }

    #[test]
    fn launcher_browser_template_has_reasonable_defaults() {
        let capsule = create_browser_capsule(
            "chrome",
            &std::path::PathBuf::from("/usr/bin/google-chrome"),
            "sha256:expected",
        );

        assert_eq!(capsule.id(), "chrome");
        assert!(capsule.sandbox_config().filesystem.contains_key("/tmp"));
        assert!(!capsule
            .sandbox_config()
            .network
            .blocked_hosts
            .is_empty());
    }

    #[test]
    fn launcher_manages_instance_lifecycle() {
        let mut launcher = setup_launcher();
        let instance_id = launcher.launch_governed_app("test_chrome").unwrap();
        assert_eq!(launcher.list_running().len(), 1);

        let stop_result = launcher.stop_app(&instance_id);
        assert!(stop_result.is_ok());
        assert_eq!(launcher.list_running().len(), 0);
    }
}
