/// Execution Governance Policy Engine
///
/// Defines deterministic rules for:
/// - Resource access (filesystem, network, devices)
/// - Capsule execution rights
/// - Permission denial/allowance based on structured policy
///
/// All decisions are:
/// - Deterministic (same input → same output)
/// - Rule-based (derivable from explicit rules)
/// - Auditible (only rule name and decision logged, no content)

use serde::{Deserialize, Serialize};

/// Governance decision for an access request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Access is allowed.
    Allow,
    /// Access is denied.
    Deny,
    /// Access is restricted (e.g., audited, rate-limited, but allowed).
    Restricted,
}

/// Represents an access control rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Subject (e.g., "chrome", "firefox").
    pub subject: String,
    /// Resource (e.g., "/tmp", "duckduckgo.com", "device:/dev/audio").
    pub resource: String,
    /// Action (e.g., "read", "write", "connect_to", "execute").
    pub action: String,
    /// Effect (Allow, Deny, Restricted).
    pub effect: Decision,
    /// Optional priority (higher = evaluated first). Default: 0.
    pub priority: i32,
}

impl PolicyRule {
    /// Creates a new policy rule.
    pub fn new(
        subject: String,
        resource: String,
        action: String,
        effect: Decision,
        priority: i32,
    ) -> Self {
        Self {
            subject,
            resource,
            action,
            effect,
            priority,
        }
    }

    /// Checks if a rule matches a request.
    pub fn matches(&self, subject: &str, resource: &str, action: &str) -> bool {
        self.subject == subject && self.resource == resource && self.action == action
    }
}

/// Represents an access request to be evaluated.
#[derive(Debug, Clone)]
pub struct AccessRequest {
    /// Capsule ID requesting access.
    pub capsule_id: String,
    /// Resource being accessed (path, hostname, device, etc.).
    pub resource: String,
    /// Action being performed (read, write, connect, execute, etc.).
    pub action: String,
    /// Timestamp of the request (seconds since epoch).
    pub timestamp: u64,
}

impl AccessRequest {
    /// Creates a new access request.
    pub fn new(capsule_id: String, resource: String, action: String, timestamp: u64) -> Self {
        Self {
            capsule_id,
            resource,
            action,
            timestamp,
        }
    }
}

/// Policy context holding all evaluation rules.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// All active policy rules, sorted by priority (highest first).
    pub rules: Vec<PolicyRule>,
    /// Default decision if no rule matches.
    pub default_decision: Decision,
}

impl PolicyContext {
    /// Creates a new policy context with an empty rule set.
    pub fn new(default_decision: Decision) -> Self {
        Self {
            rules: Vec::new(),
            default_decision,
        }
    }

    /// Adds a rule to the policy context.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        // Sort by priority (descending).
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Removes all rules matching a subject.
    pub fn remove_rules_for_subject(&mut self, subject: &str) {
        self.rules.retain(|r| r.subject != subject);
    }

    /// Evaluates an access request against all rules.
    pub fn evaluate(&self, request: &AccessRequest) -> Decision {
        // Find the first matching rule (highest priority).
        for rule in &self.rules {
            if rule.matches(&request.capsule_id, &request.resource, &request.action) {
                return rule.effect;
            }
        }
        // No matching rule; use default.
        self.default_decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_policy() -> PolicyContext {
        let mut policy = PolicyContext::new(Decision::Deny);

        // Chrome can connect to DuckDuckGo
        policy.add_rule(PolicyRule::new(
            "chrome".to_string(),
            "duckduckgo.com".to_string(),
            "connect_to".to_string(),
            Decision::Allow,
            100,
        ));

        // Chrome is explicitly denied access to tracking domains
        policy.add_rule(PolicyRule::new(
            "chrome".to_string(),
            "tracking.example.com".to_string(),
            "connect_to".to_string(),
            Decision::Deny,
            110, // Higher priority to override default
        ));

        // Chrome can read /tmp (restricted, audited)
        policy.add_rule(PolicyRule::new(
            "chrome".to_string(),
            "/tmp".to_string(),
            "read".to_string(),
            Decision::Restricted,
            50,
        ));

        // Firefox can access any host (less restrictive)
        policy.add_rule(PolicyRule::new(
            "firefox".to_string(),
            "*".to_string(),
            "connect_to".to_string(),
            Decision::Restricted,
            50,
        ));

        policy
    }

    #[test]
    fn policy_allows_whitelisted_access() {
        let policy = create_test_policy();
        let request = AccessRequest::new(
            "chrome".to_string(),
            "duckduckgo.com".to_string(),
            "connect_to".to_string(),
            0,
        );
        assert_eq!(policy.evaluate(&request), Decision::Allow);
    }

    #[test]
    fn policy_denies_blacklisted_access() {
        let policy = create_test_policy();
        let request = AccessRequest::new(
            "chrome".to_string(),
            "tracking.example.com".to_string(),
            "connect_to".to_string(),
            0,
        );
        assert_eq!(policy.evaluate(&request), Decision::Deny);
    }

    #[test]
    fn policy_uses_default_for_unmatched_request() {
        let policy = create_test_policy();
        let request = AccessRequest::new(
            "chrome".to_string(),
            "unknown-site.com".to_string(),
            "connect_to".to_string(),
            0,
        );
        assert_eq!(policy.evaluate(&request), Decision::Deny);
    }

    #[test]
    fn policy_respects_rule_priority() {
        let mut policy = PolicyContext::new(Decision::Allow);

        // Lower priority: allow
        policy.add_rule(PolicyRule::new(
            "app".to_string(),
            "resource.com".to_string(),
            "access".to_string(),
            Decision::Allow,
            50,
        ));

        // Higher priority: deny (should override)
        policy.add_rule(PolicyRule::new(
            "app".to_string(),
            "resource.com".to_string(),
            "access".to_string(),
            Decision::Deny,
            100,
        ));

        let request = AccessRequest::new(
            "app".to_string(),
            "resource.com".to_string(),
            "access".to_string(),
            0,
        );
        assert_eq!(policy.evaluate(&request), Decision::Deny);
    }

    #[test]
    fn policy_add_and_remove_rules() {
        let mut policy = PolicyContext::new(Decision::Deny);
        policy.add_rule(PolicyRule::new(
            "chrome".to_string(),
            "example.com".to_string(),
            "connect".to_string(),
            Decision::Allow,
            100,
        ));
        assert_eq!(policy.rules.len(), 1);

        policy.remove_rules_for_subject("chrome");
        assert_eq!(policy.rules.len(), 0);

        let request = AccessRequest::new(
            "chrome".to_string(),
            "example.com".to_string(),
            "connect".to_string(),
            0,
        );
        assert_eq!(policy.evaluate(&request), Decision::Deny);
    }

    #[test]
    fn policy_restricted_access_is_allowed_but_audited() {
        let policy = create_test_policy();
        let request = AccessRequest::new(
            "chrome".to_string(),
            "/tmp".to_string(),
            "read".to_string(),
            0,
        );
        assert_eq!(policy.evaluate(&request), Decision::Restricted);
    }
}
