/// Network Access Guard
///
/// Controls and validates network requests from execution capsules.
/// Enforces:
/// - Destination host whitelisting/blacklisting
/// - Protocol validation
/// - Prevention of telemetry/tracking domains
/// - Rate limiting (optional, metadata-only)
///
/// No payload inspection; only metadata (host, port, protocol, capsule_id) is examined.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::egl_policy::{AccessRequest, Decision, PolicyContext};

/// Represents a network access request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAccessRequest {
    /// Capsule ID originating the request.
    pub capsule_id: String,
    /// Destination hostname or IP.
    pub destination_host: String,
    /// Destination port (1-65535, or 0 for any).
    pub destination_port: u16,
    /// Protocol (tcp, udp, tls, https, etc.).
    pub protocol: String,
    /// Timestamp of the request (seconds since epoch).
    pub timestamp: u64,
}

impl NetworkAccessRequest {
    /// Creates a new network access request.
    pub fn new(
        capsule_id: String,
        destination_host: String,
        destination_port: u16,
        protocol: String,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            capsule_id,
            destination_host,
            destination_port,
            protocol,
            timestamp,
        }
    }

    /// Converts this network request to a generic access request for policy evaluation.
    pub fn to_access_request(&self) -> AccessRequest {
        let resource = format!("{}:{}", self.destination_host, self.destination_port);
        AccessRequest::new(
            self.capsule_id.clone(),
            resource,
            format!("connect_{}", self.protocol.to_lowercase()),
            self.timestamp,
        )
    }
}

/// Global network access guard configuration.
#[derive(Debug, Clone)]
pub struct NetworkGuard {
    /// Trusted whitelisted hosts (DNS names, IPs, or wildcards).
    pub trusted_hosts: HashSet<String>,
    /// Known telemetry/tracking domains to always block.
    pub tracking_domains: HashSet<String>,
    /// Allowed protocols for network access.
    pub allowed_protocols: HashSet<String>,
}

impl NetworkGuard {
    /// Creates a new network guard with safe defaults.
    pub fn new() -> Self {
        let mut guard = Self {
            trusted_hosts: HashSet::new(),
            tracking_domains: HashSet::new(),
            allowed_protocols: HashSet::new(),
        };

        // Default safe protocols
        guard.allowed_protocols.insert("tcp".to_string());
        guard.allowed_protocols.insert("udp".to_string());
        guard.allowed_protocols.insert("tls".to_string());
        guard.allowed_protocols.insert("https".to_string());

        // Default tracked domains (common telemetry/ad services)
        guard
            .tracking_domains
            .insert("tracking.example.com".to_string());
        guard.tracking_domains.insert("analytics.google.com".to_string());
        guard
            .tracking_domains
            .insert("facebook.com".to_string());
        guard.tracking_domains.insert("gstatic.com".to_string());

        guard
    }

    /// Adds a host to the trusted whitelist.
    pub fn add_trusted_host(&mut self, host: &str) {
        self.trusted_hosts.insert(host.to_string());
    }

    /// Removes a host from the trusted whitelist.
    pub fn remove_trusted_host(&mut self, host: &str) {
        self.trusted_hosts.remove(host);
    }

    /// Adds a domain to the tracking/telemetry blacklist.
    pub fn add_tracking_domain(&mut self, domain: &str) {
        self.tracking_domains.insert(domain.to_string());
    }

    /// Checks if a host is known to be a tracking domain.
    fn is_tracking_domain(&self, host: &str) -> bool {
        // Exact match
        if self.tracking_domains.contains(host) {
            return true;
        }

        // Subdomain match (simple heuristic)
        for tracking_host in &self.tracking_domains {
            if host.ends_with(&format!(".{}", tracking_host)) {
                return true;
            }
        }

        false
    }

    /// Checks if a protocol is allowed.
    fn is_protocol_allowed(&self, protocol: &str) -> bool {
        self.allowed_protocols.contains(&protocol.to_lowercase())
    }

    /// Validates a network request at the guard level (host and protocol).
    /// This is the first-pass check before policy evaluation.
    pub fn validate_request(&self, request: &NetworkAccessRequest) -> Decision {
        // Check protocol first
        if !self.is_protocol_allowed(&request.protocol) {
            return Decision::Deny;
        }

        // Check if destination is in the tracking blacklist
        if self.is_tracking_domain(&request.destination_host) {
            return Decision::Deny;
        }

        // If whitelisted hosts are defined, only allow those
        if !self.trusted_hosts.is_empty() && !self.trusted_hosts.contains(&request.destination_host) {
            // Check for wildcard allowance
            if !self.trusted_hosts.contains("*") {
                return Decision::Deny;
            }
        }

        // If we reach here, basic validation passed; policy will make final decision
        Decision::Allow
    }
}

impl Default for NetworkGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Evaluates a network access request using both guard validation and policy context.
pub fn check_network_access(
    request: &NetworkAccessRequest,
    guard: &NetworkGuard,
    policy: &PolicyContext,
) -> Decision {
    // First: guard-level validation (protocol, known tracking domains)
    let guard_decision = guard.validate_request(request);
    if guard_decision == Decision::Deny {
        return Decision::Deny;
    }

    // Second: policy-level evaluation (rules and default)
    let access_request = request.to_access_request();
    policy.evaluate(&access_request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_guard() -> NetworkGuard {
        let mut guard = NetworkGuard::new();
        guard.add_trusted_host("duckduckgo.com");
        guard
    }

    fn create_test_policy() -> PolicyContext {
        let mut policy = PolicyContext::new(Decision::Deny);
        policy.add_rule(crate::egl_policy::PolicyRule::new(
            "chrome".to_string(),
            "duckduckgo.com:443".to_string(),
            "connect_https".to_string(),
            Decision::Allow,
            100,
        ));
        policy
    }

    #[test]
    fn guard_allows_valid_protocol() {
        let guard = NetworkGuard::new();
        let request = NetworkAccessRequest::new(
            "chrome".to_string(),
            "example.com".to_string(),
            443,
            "https".to_string(),
        );
        assert_eq!(guard.validate_request(&request), Decision::Allow);
    }

    #[test]
    fn guard_denies_invalid_protocol() {
        let guard = NetworkGuard::new();
        let request = NetworkAccessRequest::new(
            "chrome".to_string(),
            "example.com".to_string(),
            9999,
            "raw_socket".to_string(),
        );
        assert_eq!(guard.validate_request(&request), Decision::Deny);
    }

    #[test]
    fn guard_blocks_known_tracking_domains() {
        let guard = NetworkGuard::new();
        let request = NetworkAccessRequest::new(
            "chrome".to_string(),
            "tracking.example.com".to_string(),
            443,
            "https".to_string(),
        );
        assert_eq!(guard.validate_request(&request), Decision::Deny);
    }

    #[test]
    fn guard_blocks_subdomains_of_tracking_domains() {
        let guard = NetworkGuard::new();
        let request = NetworkAccessRequest::new(
            "chrome".to_string(),
            "subdomain.tracking.example.com".to_string(),
            443,
            "https".to_string(),
        );
        assert_eq!(guard.validate_request(&request), Decision::Deny);
    }

    #[test]
    fn full_network_check_allows_whitelisted_duckduckgo() {
        let guard = create_test_guard();
        let policy = create_test_policy();
        let request = NetworkAccessRequest::new(
            "chrome".to_string(),
            "duckduckgo.com".to_string(),
            443,
            "https".to_string(),
        );
        assert_eq!(check_network_access(&request, &guard, &policy), Decision::Allow);
    }

    #[test]
    fn full_network_check_denies_tracking_domain() {
        let guard = create_test_guard();
        let policy = create_test_policy();
        let request = NetworkAccessRequest::new(
            "chrome".to_string(),
            "tracking.example.com".to_string(),
            443,
            "https".to_string(),
        );
        assert_eq!(check_network_access(&request, &guard, &policy), Decision::Deny);
    }

    #[test]
    fn full_network_check_denies_unlisted_host_with_default_deny() {
        let guard = create_test_guard();
        let policy = create_test_policy();
        let request = NetworkAccessRequest::new(
            "chrome".to_string(),
            "unknown.com".to_string(),
            443,
            "https".to_string(),
        );
        assert_eq!(check_network_access(&request, &guard, &policy), Decision::Deny);
    }

    #[test]
    fn guard_add_and_remove_trusted_hosts() {
        let mut guard = NetworkGuard::new();
        guard.add_trusted_host("example.com");
        assert!(guard.trusted_hosts.contains("example.com"));

        guard.remove_trusted_host("example.com");
        assert!(!guard.trusted_hosts.contains("example.com"));
    }

    #[test]
    fn network_request_conversion_to_access_request() {
        let net_request = NetworkAccessRequest::new(
            "chrome".to_string(),
            "example.com".to_string(),
            443,
            "https".to_string(),
        );
        let access_request = net_request.to_access_request();
        assert_eq!(access_request.capsule_id, "chrome");
        assert_eq!(access_request.resource, "example.com:443");
    }
}
