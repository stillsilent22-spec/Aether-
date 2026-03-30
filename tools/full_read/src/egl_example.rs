/// EXECUTION GOVERNANCE LAYER – FULL END-TO-END EXAMPLE
///
/// This file demonstrates a complete workflow:
/// 1. Define two capsules (Chrome, Firefox)
/// 2. Set up policies and network guards
/// 3. Verify integrity
/// 4. Launch capsules
/// 5. Handle runtime access requests (network, filesystem)
/// 6. Verify decisions against rules
///
/// This example is self-contained and fully runnable as a test.

#[cfg(test)]
mod egl_full_example {
    use crate::capsule::{Capsule, NetworkConfig, Permission, SandboxConfig, IntegrityStatus};
    use crate::egl_policy::{Decision, PolicyRule};
    use crate::egl_api::GoverningLauncher;
    use crate::orchestrator::MockAetherClient;
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// Comprehensive end-to-end test demonstrating full EGL workflow.
    #[test]
    fn full_egl_workflow_chrome_and_firefox() {
        println!("\n=== EXECUTION GOVERNANCE LAYER – FULL WORKFLOW ===\n");

        // =========================================================================
        // SETUP: Define Capsules
        // =========================================================================
        println!("STEP 1: Define Capsules (Chrome & Firefox)\n");

        // Chrome capsule
        let mut chrome_fs = HashMap::new();
        chrome_fs.insert("/tmp".to_string(), Permission::ReadWrite);
        chrome_fs.insert("/home/user/Downloads".to_string(), Permission::ReadWrite);

        let chrome_network = NetworkConfig {
            allowed_hosts: vec![
                "duckduckgo.com".to_string(),
                "*.duckduckgo.com".to_string(),
            ],
            blocked_hosts: vec![
                "facebook.com".to_string(),
                "tracking.example.com".to_string(),
            ],
            allowed_protocols: vec!["tcp".to_string(), "tls".to_string(), "https".to_string()],
            default_policy: false,
        };

        let chrome_sandbox = SandboxConfig {
            filesystem: chrome_fs,
            network: chrome_network,
            devices: HashMap::new(),
            env_whitelist: vec!["PATH".to_string(), "HOME".to_string(), "LANG".to_string()],
        };

        let chrome = Capsule::new(
            "chrome".to_string(),
            PathBuf::from("/usr/bin/google-chrome"),
            "sha256:chrome_expected_hash_123abc".to_string(),
            chrome_sandbox,
            "Google Chrome Browser".to_string(),
        );

        println!("✓ Registered capsule: {}", chrome.id());
        println!("  Binary: {:?}", chrome.binary_path());
        println!("  Network hosts: {:?}", chrome.sandbox_config().network.allowed_hosts);

        // Firefox capsule
        let mut firefox_fs = HashMap::new();
        firefox_fs.insert("/tmp".to_string(), Permission::ReadWrite);
        firefox_fs.insert("/home/user/.mozilla".to_string(), Permission::ReadWrite);

        let firefox_network = NetworkConfig {
            allowed_hosts: vec!["duckduckgo.com".to_string()],
            blocked_hosts: vec!["gstatic.com".to_string(), "google-analytics.com".to_string()],
            allowed_protocols: vec!["tcp".to_string(), "tls".to_string()],
            default_policy: false,
        };

        let firefox_sandbox = SandboxConfig {
            filesystem: firefox_fs,
            network: firefox_network,
            devices: HashMap::new(),
            env_whitelist: vec!["PATH".to_string(), "HOME".to_string()],
        };

        let firefox = Capsule::new(
            "firefox".to_string(),
            PathBuf::from("/usr/bin/firefox"),
            "sha256:firefox_expected_hash_456def".to_string(),
            firefox_sandbox,
            "Mozilla Firefox Browser".to_string(),
        );

        println!("✓ Registered capsule: {}", firefox.id());
        println!("  Binary: {:?}", firefox.binary_path());

        // =========================================================================
        // SETUP: Initialize GoverningLauncher
        // =========================================================================
        println!("\nSTEP 2: Initialize GoverningLauncher\n");

        let mut launcher = GoverningLauncher::new();
        launcher.register_capsule(chrome.clone());
        launcher.register_capsule(firefox.clone());

        println!("✓ Registered {} capsules", launcher.list_capsules().len());

        // =========================================================================
        // SETUP: Configure Aether Client (Mock)
        // =========================================================================
        println!("\nSTEP 3: Configure Aether Client (Mocked)\n");

        let mut aether_mock = MockAetherClient::new();
        aether_mock.add_binary(
            "/usr/bin/google-chrome".to_string(),
            IntegrityStatus::Clean, // Chrome binary is clean
        );
        aether_mock.add_binary(
            "/usr/bin/firefox".to_string(),
            IntegrityStatus::Clean, // Firefox binary is clean
        );

        launcher.set_aether_client(Box::new(aether_mock));
        println!("✓ Aether client configured (both binaries marked as Clean)");

        // =========================================================================
        // SETUP: Define Policies
        // =========================================================================
        println!("\nSTEP 4: Define Governance Policies\n");

        // Chrome can connect to DuckDuckGo
        launcher.add_policy_rule(PolicyRule::new(
            "chrome".to_string(),
            "duckduckgo.com:443".to_string(),
            "connect_https".to_string(),
            Decision::Allow,
            100,
        ));

        // Chrome explicitly denied Facebook
        launcher.add_policy_rule(PolicyRule::new(
            "chrome".to_string(),
            "facebook.com:443".to_string(),
            "connect_https".to_string(),
            Decision::Deny,
            110,
        ));

        // Firefox can read from /tmp (restricted, audited)
        launcher.add_policy_rule(PolicyRule::new(
            "firefox".to_string(),
            "/tmp".to_string(),
            "read".to_string(),
            Decision::Restricted,
            50,
        ));

        println!("✓ Policy 1: Chrome → DuckDuckGo:443 (Allow)");
        println!("✓ Policy 2: Chrome → Facebook:443 (Deny)");
        println!("✓ Policy 3: Firefox → /tmp (Restricted/Audited)");

        // =========================================================================
        // SETUP: Configure Network Guard
        // =========================================================================
        println!("\nSTEP 5: Configure Network Guard\n");

        launcher.add_trusted_host("duckduckgo.com");
        launcher.add_tracking_domain("tracking.example.com");
        launcher.add_tracking_domain("facebook.com");

        println!("✓ Whitelisted: duckduckgo.com");
        println!("✓ Blacklisted (tracking): tracking.example.com, facebook.com");

        // =========================================================================
        // EXECUTION: Launch Chrome
        // =========================================================================
        println!("\nSTEP 6: Launch Chrome\n");

        let chrome_instance = launcher
            .launch_governed_app("chrome")
            .expect("Chrome should launch (integrity Clean)");

        println!("✓ Chrome launched successfully");
        println!("  Instance ID: {}", chrome_instance);
        println!("  Running instances: {}", launcher.list_running().len());

        // =========================================================================
        // EXECUTION: Launch Firefox
        // =========================================================================
        println!("\nSTEP 7: Launch Firefox\n");

        let firefox_instance = launcher
            .launch_governed_app("firefox")
            .expect("Firefox should launch (integrity Clean)");

        println!("✓ Firefox launched successfully");
        println!("  Instance ID: {}", firefox_instance);
        println!("  Running instances: {}", launcher.list_running().len());

        // =========================================================================
        // RUNTIME: Test Network Access – Chrome to DuckDuckGo (Allowed)
        // =========================================================================
        println!("\nSTEP 8: Network Access Test – Chrome → DuckDuckGo\n");

        match launcher.handle_network_access(&chrome_instance, "duckduckgo.com", 443, "https") {
            Ok(_) => println!("✓ Access ALLOWED (policy + guard OK)"),
            Err(e) => panic!("Expected allow, got: {}", e),
        }

        // =========================================================================
        // RUNTIME: Test Network Access – Chrome to Facebook (Denied)
        // =========================================================================
        println!("\nSTEP 9: Network Access Test – Chrome → Facebook (Should Deny)\n");

        match launcher.handle_network_access(&chrome_instance, "facebook.com", 443, "https") {
            Ok(_) => panic!("Expected deny for facebook.com"),
            Err(e) => println!("✓ Access DENIED: {}", e),
        }

        // =========================================================================
        // RUNTIME: Test Network Access – Chrome to Tracking Domain
        // =========================================================================
        println!("\nSTEP 10: Network Access Test – Chrome → Tracking Domain\n");

        match launcher.handle_network_access(
            &chrome_instance,
            "tracking.example.com",
            443,
            "https",
        ) {
            Ok(_) => panic!("Expected deny for tracking domain"),
            Err(e) => println!("✓ Access DENIED: {}", e),
        }

        // =========================================================================
        // RUNTIME: Test Filesystem Access – Firefox read /tmp (Restricted)
        // =========================================================================
        println!("\nSTEP 11: Filesystem Access Test – Firefox read /tmp\n");

        match launcher.handle_filesystem_access(&firefox_instance, "/tmp", "read") {
            Ok(_) => println!("✓ Access RESTRICTED (audited, allowed)"),
            Err(e) => panic!("Expected restrict, got: {}", e),
        }

        // =========================================================================
        // RUNTIME: Test Filesystem Access – Firefox write /etc (Should Deny)
        // =========================================================================
        println!("\nSTEP 12: Filesystem Access Test – Firefox write /etc\n");

        match launcher.handle_filesystem_access(&firefox_instance, "/etc/passwd", "write") {
            Ok(_) => panic!("Expected deny for /etc/passwd write"),
            Err(e) => println!("✓ Access DENIED: {}", e),
        }

        // =========================================================================
        // CLEANUP: Stop Instances
        // =========================================================================
        println!("\nSTEP 13: Stop Instances\n");

        launcher
            .stop_app(&chrome_instance)
            .expect("Chrome stop should succeed");
        println!("✓ Chrome stopped");

        launcher
            .stop_app(&firefox_instance)
            .expect("Firefox stop should succeed");
        println!("✓ Firefox stopped");

        println!("  Running instances: {}", launcher.list_running().len());

        // =========================================================================
        // SUMMARY
        // =========================================================================
        println!("\n=== WORKFLOW COMPLETE ===\n");
        println!("Summary:");
        println!("  ✓ Defined 2 capsules (Chrome, Firefox)");
        println!("  ✓ Verified integrity via Aether (both Clean)");
        println!("  ✓ Launched both applications");
        println!("  ✓ Tested network access (Allow, Deny, Tracking-block)");
        println!("  ✓ Tested filesystem access (Restricted, Deny)");
        println!("  ✓ Stopped applications gracefully");
        println!("\nAll governance decisions were deterministic, rule-based, and auditable.");
        println!("No content was read, no privacy was violated.\n");
    }

    /// Test case: Tampered binary prevents launch.
    #[test]
    fn tampered_binary_prevents_launch() {
        println!("\n=== INTEGRITY FAILURE TEST ===\n");

        let mut launcher = GoverningLauncher::new();

        let capsule = Capsule::new(
            "malicious".to_string(),
            PathBuf::from("/usr/bin/malicious"),
            "sha256:safe_hash".to_string(),
            {
                let mut fs = HashMap::new();
                fs.insert("/tmp".to_string(), Permission::ReadWrite);
                SandboxConfig {
                    filesystem: fs,
                    network: NetworkConfig {
                        allowed_hosts: vec![],
                        blocked_hosts: vec![],
                        allowed_protocols: vec![],
                        default_policy: false,
                    },
                    devices: HashMap::new(),
                    env_whitelist: vec![],
                }
            },
            "Malicious app".to_string(),
        );

        launcher.register_capsule(capsule);

        let mut aether_mock = MockAetherClient::new();
        aether_mock.add_binary(
            "/usr/bin/malicious".to_string(),
            IntegrityStatus::Tampered, // Binary is tampered!
        );
        launcher.set_aether_client(Box::new(aether_mock));

        match launcher.launch_governed_app("malicious") {
            Ok(_) => panic!("Should NOT launch tampered binary"),
            Err(e) => {
                println!("✓ Launch blocked: {}", e);
                println!("✓ Integrity verification prevented execution\n");
            }
        }
    }
}
