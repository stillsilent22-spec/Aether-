/// Execution Capsule Model
///
/// An execution capsule represents a sandboxed application with:
/// - A reference to the application binary (path)
/// - Sandbox configuration (filesystem, network, device permissions)
/// - Integrity fingerprint/hash for verification
///
/// Capsules are stateless, immutable descriptors. The Orchestrator
/// instantiates and manages running instances.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Represents permissions for a resource type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Permission {
    /// Deny all access.
    Deny,
    /// Allow read-only access.
    ReadOnly,
    /// Allow read and write.
    ReadWrite,
    /// Allow full access (dangerous).
    Full,
}

/// Sandbox configuration for an execution capsule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Filesystem permissions (path patterns -> Permission).
    pub filesystem: HashMap<String, Permission>,
    /// Network access configuration.
    pub network: NetworkConfig,
    /// Device access permissions.
    pub devices: HashMap<String, Permission>,
    /// Environment variables (whitelist).
    pub env_whitelist: Vec<String>,
}

/// Network configuration for a capsule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Whitelisted destination hosts (DNS names or IPs).
    pub allowed_hosts: Vec<String>,
    /// Blacklisted hosts (deny override).
    pub blocked_hosts: Vec<String>,
    /// Allowed protocols (tcp, udp, https, etc.).
    pub allowed_protocols: Vec<String>,
    /// Default allow or deny for unlisted hosts.
    pub default_policy: bool,
}

/// Represents an execution capsule descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsule {
    /// Unique capsule identifier (e.g., "chrome", "firefox").
    pub id: String,
    /// Path to the application binary.
    pub binary_path: PathBuf,
    /// Expected integrity hash (computed by Aether).
    /// Format: "sha256:hexhash" or similar.
    pub expected_integrity_hash: String,
    /// Sandbox configuration.
    pub sandbox_config: SandboxConfig,
    /// Human-readable description.
    pub description: String,
}

/// Status of integrity verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    /// Binary is unmodified and trusted.
    Clean,
    /// Binary does not exist or cannot be read.
    Missing,
    /// Binary has been tampered with (hash mismatch).
    Tampered,
    /// Hash cannot be computed (permission denied, bad format, etc.).
    VerificationFailed,
}

impl Capsule {
    /// Creates a new capsule descriptor.
    pub fn new(
        id: String,
        binary_path: PathBuf,
        expected_integrity_hash: String,
        sandbox_config: SandboxConfig,
        description: String,
    ) -> Self {
        Self {
            id,
            binary_path,
            expected_integrity_hash,
            sandbox_config,
            description,
        }
    }

    /// Returns the capsule ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the binary path.
    pub fn binary_path(&self) -> &PathBuf {
        &self.binary_path
    }

    /// Returns a reference to the sandbox configuration.
    pub fn sandbox_config(&self) -> &SandboxConfig {
        &self.sandbox_config
    }

    /// Checks if a filesystem path matches the capsule's allowed paths.
    pub fn is_path_allowed(&self, path: &str, access_type: &str) -> bool {
        for (pattern, perm) in &self.sandbox_config.filesystem {
            if path.starts_with(pattern) {
                return match (access_type, perm) {
                    ("read", Permission::ReadOnly) => true,
                    ("read", Permission::ReadWrite) => true,
                    ("read", Permission::Full) => true,
                    ("write", Permission::ReadWrite) => true,
                    ("write", Permission::Full) => true,
                    (_, Permission::Full) => true,
                    _ => false,
                };
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_capsule() -> Capsule {
        let mut fs_perms = HashMap::new();
        fs_perms.insert("/tmp".to_string(), Permission::ReadWrite);
        fs_perms.insert("/home/user/Downloads".to_string(), Permission::ReadOnly);

        let network_config = NetworkConfig {
            allowed_hosts: vec!["duckduckgo.com".to_string()],
            blocked_hosts: vec!["tracking.example.com".to_string()],
            allowed_protocols: vec!["tcp".to_string(), "tls".to_string()],
            default_policy: false,
        };

        let sandbox_config = SandboxConfig {
            filesystem: fs_perms,
            network: network_config,
            devices: HashMap::new(),
            env_whitelist: vec!["PATH".to_string(), "HOME".to_string()],
        };

        Capsule::new(
            "chrome".to_string(),
            PathBuf::from("/usr/bin/google-chrome"),
            "sha256:abc123def456".to_string(),
            sandbox_config,
            "Google Chrome browser".to_string(),
        )
    }

    #[test]
    fn capsule_allows_whitelisted_paths() {
        let capsule = create_test_capsule();
        assert!(capsule.is_path_allowed("/tmp/file.txt", "read"));
        assert!(capsule.is_path_allowed("/tmp/file.txt", "write"));
    }

    #[test]
    fn capsule_restricts_write_to_readonly_paths() {
        let capsule = create_test_capsule();
        assert!(capsule.is_path_allowed("/home/user/Downloads/file.txt", "read"));
        assert!(!capsule.is_path_allowed("/home/user/Downloads/file.txt", "write"));
    }

    #[test]
    fn capsule_denies_unlisted_paths() {
        let capsule = create_test_capsule();
        assert!(!capsule.is_path_allowed("/root/secret.txt", "read"));
    }

    #[test]
    fn capsule_creation_and_access() {
        let capsule = create_test_capsule();
        assert_eq!(capsule.id(), "chrome");
        assert_eq!(
            capsule.binary_path(),
            &PathBuf::from("/usr/bin/google-chrome")
        );
        assert_eq!(capsule.sandbox_config().env_whitelist.len(), 2);
    }
}
