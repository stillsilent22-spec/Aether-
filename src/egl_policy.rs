/// Decision returned by the EGL (Execution Governance Layer) policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Restricted,
    Deny,
}

/// A single policy rule.
///
/// - `capsule_id`: exact capsule ID or `"*"` wildcard
/// - `resource`: resource path / type prefix to match
/// - `action`: action string, e.g. `"read"`, `"write"`, `"connect"`, or `"*"`
/// - `decision`: decision to apply when this rule matches
/// - `priority`: higher value takes precedence when multiple rules match
#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub capsule_id: String,
    pub resource: String,
    pub action: String,
    pub decision: Decision,
    pub priority: i32,
}

impl PolicyRule {
    pub fn new(
        capsule_id: String,
        resource: String,
        action: String,
        decision: Decision,
        priority: i32,
    ) -> Self {
        Self { capsule_id, resource, action, decision, priority }
    }

    fn matches(&self, req: &AccessRequest) -> bool {
        let capsule_ok = self.capsule_id == "*" || self.capsule_id == req.capsule_id;
        let resource_ok = self.resource == "*" || req.path.starts_with(&self.resource);
        let action_ok = self.action == "*" || self.action == req.action;
        capsule_ok && resource_ok && action_ok
    }
}

/// Holds rules and a default fallback decision.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    default_decision: Decision,
    rules: Vec<PolicyRule>,
}

impl PolicyContext {
    pub fn new(default: Decision) -> Self {
        Self { default_decision: default, rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Evaluate access: highest-priority matching rule wins; default applies when no rule matches.
    pub fn evaluate(&self, req: &AccessRequest) -> Decision {
        let mut best: Option<&PolicyRule> = None;
        for rule in &self.rules {
            if rule.matches(req) {
                match best {
                    None => best = Some(rule),
                    Some(b) if rule.priority > b.priority => best = Some(rule),
                    _ => {}
                }
            }
        }
        best.map(|r| r.decision).unwrap_or(self.default_decision)
    }
}

/// Describes a resource access attempt.
#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub capsule_id: String,
    pub path: String,
    pub action: String,
    pub timestamp: u64,
}

impl AccessRequest {
    pub fn new(capsule_id: String, path: String, action: String, timestamp: u64) -> Self {
        Self { capsule_id, path, action, timestamp }
    }
}
