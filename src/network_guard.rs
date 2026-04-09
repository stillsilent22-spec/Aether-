use crate::egl_policy::{AccessRequest, Decision, PolicyContext};

/// Tracks which hosts a capsule is permitted to reach.
#[derive(Debug, Default)]
pub struct NetworkGuard {
    trusted_hosts: Vec<String>,
}

impl NetworkGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whitelist a hostname for outgoing connections.
    pub fn add_trusted_host(&mut self, host: &str) {
        let h = host.trim().to_lowercase();
        if !self.trusted_hosts.contains(&h) {
            self.trusted_hosts.push(h);
        }
    }

    pub fn is_trusted(&self, host: &str) -> bool {
        let h = host.trim().to_lowercase();
        self.trusted_hosts.contains(&h)
    }
}

/// Describes an outgoing network access attempt made by a capsule.
#[derive(Debug, Clone)]
pub struct NetworkAccessRequest {
    pub capsule_id: String,
    pub destination_host: String,
    pub destination_port: u16,
    pub protocol: String,
}

impl NetworkAccessRequest {
    pub fn new(
        capsule_id: String,
        destination_host: String,
        port: u16,
        protocol: String,
    ) -> Self {
        Self {
            capsule_id,
            destination_host,
            destination_port: port,
            protocol,
        }
    }
}

/// Evaluate whether a capsule's outgoing network access should be permitted.
///
/// Decision logic (ordered):
/// 1. Build an `AccessRequest` from capsule + destination and evaluate the policy.
/// 2. An explicit `Decision::Deny` from the policy always wins.
/// 3. If the destination host is in the guard's trusted list → `Allow`.
/// 4. Otherwise return the policy decision as-is.
pub fn check_network_access(
    request: &NetworkAccessRequest,
    guard: &NetworkGuard,
    policy: &PolicyContext,
) -> Decision {
    let access_req = AccessRequest::new(
        request.capsule_id.clone(),
        format!("network:{}:{}", request.destination_host, request.destination_port),
        "connect".to_owned(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );

    let policy_decision = policy.evaluate(&access_req);

    if policy_decision == Decision::Deny {
        return Decision::Deny;
    }

    if guard.is_trusted(&request.destination_host) {
        return Decision::Allow;
    }

    policy_decision
}
