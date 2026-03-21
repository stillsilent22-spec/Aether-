/// EXECUTION GOVERNANCE LAYER (EGL) – COMPREHENSIVE USAGE GUIDE
///
/// This document explains how to use the Execution Governance Layer to safely
/// and deterministically manage application execution on a desktop client.
///
/// # Überblick (Overview)
///
/// Das Execution Governance Layer (EGL) ist ein lokales, deterministisches
/// Kontrollsystem für die Ausführung von Desktop-Anwendungen (z. B. Browser,
/// Dateieditoren, Media-Player). Es steuert:
///
/// - **Integrität**: Überprüfung der Binärdatei vor dem Start (via Aether)
/// - **Netzwerkzugriff**: Whitelist/Blacklist von Zielhosts
/// - **Dateisystem-Zugriff**: Richtlinienbasierte Zugriffskontrolle
/// - **Geräte-Zugriff**: Webcam, Mikrophon, USB, etc.
///
/// Alle Entscheidungen sind:
/// - Lokal (keine Cloud, keine Gegenstelle)
/// - Deterministisch (gleiche Eingabe → gleiche Ausgabe)
/// - Auditierbar (Logs nur mit Metadaten, kein Inhalt)
/// - Regelbasiert (menschenlesbar, nicht KI-basiert)
///
/// # Architektur
///
/// Das EGL besteht aus fünf Rust-Modulen:
///
/// 1. **capsule.rs** – Kapselbeschreibung
///    - Modelliert eine Anwendung mit Pfad, Sandbox-Konfiguration, Integrity-Hash
///
/// 2. **egl_policy.rs** – Governance-Regeln
///    - PolicyRule: Subject (App), Resource, Action, Effect (Allow/Deny/Restricted)
///    - PolicyContext: Wertet AccessRequests gegen Regeln aus
///
/// 3. **network_guard.rs** – Netzwerk-Gatekeeper
///    - Whitelist/Blacklist von Hosts
///    - Protokoll-Validierung
///    - Tracking-Domain-Blockierung
///
/// 4. **orchestrator.rs** – Koordinator
///    - Lädt Kapseln, verifyfizt Integrität via Aether
///    - Verwaltet laufende Instanzen
///    - Wertet Zugriffsfragen aus (Netzwerk, Dateisystem)
///
/// 5. **egl_api.rs** – Öffentliche API
///    - GoverningLauncher: High-Level-Interface für Benutzer/Admin
///    - Einfache Funktionen: launch_governed_app(), handle_network_access(), etc.
///
/// # Schneltestart (Quick Start)
///
/// ## 1. Kapseln definieren
///
/// ```rust
/// use aether_rust_shell::capsule::{Capsule, SandboxConfig, NetworkConfig, Permission};
/// use aether_rust_shell::egl_api::GoverningLauncher;
/// use std::collections::HashMap;
/// use std::path::PathBuf;
///
/// // Kapseldefinition erstellen
/// let mut fs_perms = HashMap::new();
/// fs_perms.insert("/tmp".to_string(), Permission::ReadWrite);
///
/// let network_config = NetworkConfig {
///     allowed_hosts: vec!["duckduckgo.com".to_string()],
///     blocked_hosts: vec!["facebook.com".to_string()],
///     allowed_protocols: vec!["https".to_string()],
///     default_policy: false,
/// };
///
/// let sandbox_config = SandboxConfig {
///     filesystem: fs_perms,
///     network: network_config,
///     devices: HashMap::new(),
///     env_whitelist: vec!["PATH".to_string(), "HOME".to_string()],
/// };
///
/// let chrome_capsule = Capsule::new(
///     "chrome".to_string(),
///     PathBuf::from("/usr/bin/google-chrome"),
///     "sha256:expected_hash_here".to_string(),
///     sandbox_config,
///     "Google Chrome".to_string(),
/// );
/// ```
///
/// ## 2. GoverningLauncher konfigurieren
///
/// ```rust
/// let mut launcher = GoverningLauncher::new();
///
/// // Kapsel registrieren
/// launcher.register_capsule(chrome_capsule);
///
/// // Aether-Client setzen (für echte Integritätsprüfung)
/// // launcher.set_aether_client(Box::new(RealAetherClient::new()));
///
/// // Policy-Regel hinzufügen
/// use aether_rust_shell::egl_policy::{PolicyRule, Decision};
///
/// launcher.add_policy_rule(PolicyRule::new(
///     "chrome".to_string(),
///     "duckduckgo.com:443".to_string(),
///     "connect_https".to_string(),
///     Decision::Allow,
///     100,
/// ));
/// ```
///
/// ## 3. Anwendung starten
///
/// ```rust
/// match launcher.launch_governed_app("chrome") {
///     Ok(instance_id) => println!("Chrome launched: {}", instance_id),
///     Err(e) => eprintln!("Launch failed: {}", e),
/// }
/// ```
///
/// ## 4. Runtime-Zugriffsanfragen verwalten
///
/// ```rust
/// // Netzwerkzugriff
/// if let Err(e) = launcher.handle_network_access(&instance_id, "duckduckgo.com", 443, "https") {
///     eprintln!("Network access denied: {}", e);
/// }
///
/// // Dateisystem-Zugriff
/// if let Err(e) = launcher.handle_filesystem_access(&instance_id, "/tmp/file.txt", "write") {
///     eprintln!("File access denied: {}", e);
/// }
/// ```
///
/// # Entscheidungsfluss
///
/// Wenn Chrome versucht, sich mit example.com zu verbinden:
///
/// 1. **NetworkGuard** (capsule.rs):
///    - Ist "https" erlaubtes Protokoll? Ja → Weiter
///    - Ist "example.com" in Tracking-Domains? Nein → Weiter
///    - Erste Validierung bestanden
///
/// 2. **PolicyContext** (egl_policy.rs):
///    - Gibt es Regel: "chrome" + "example.com:443" + "connect_https"? 
///    - Falls ja → Entscheidung aus Regel (Allow/Deny/Restricted)
///    - Falls nein → Standardentscheidung (Default = Deny)
///    - Entscheidung: Deny
///
/// 3. **Audit**:
///    - Log: { timestamp: 1705234567, capsule_id: "chrome", decision: "Deny", resource_type: "network" }
///    - Keine URLs, keine Inhalte, nur Metadaten
///
/// # Logging & Audit
///
/// Das EGL protokolliert nur Metadaten:
///
/// ```rust
/// struct AuditEntry {
///     timestamp: u64,           // Sekunden seit Unix-Epoch
///     capsule_id: String,       // "chrome", "firefox", etc.
///     decision: Decision,       // Allow, Deny, Restricted
///     resource_type: String,    // "network", "filesystem", "device"
/// }
/// ```
///
/// **NICHT protokolliert**:
/// - Netzwerk-Payloads
/// - Dateipfade (nur resource_type)
/// - URLs
/// - Dateiinhalte
/// - Persönliche Daten
///
/// # Aether-Integration
///
/// Aether wird nur für **Integritätsprüfung** verwendet:
///
/// 1. Kapsule "chrome" hat erwarteten Hash: "sha256:abc123..."
/// 2. Vor dem Start fragt EGL Aether: "Ist /usr/bin/google-chrome = abc123...?"
/// 3. Aether antwortet: IntegrityStatus::Clean oder IntegrityStatus::Tampered
/// 4. Falls Tampered: Kapsele wird NICHT gestartet
/// 5. Falls Clean: Kapsele wird im Sandbox gestartet
///
/// **Aether liest keine Inhalte, nur Strukturhashes!**
///
/// # Beispieldeployment für Firefox
///
/// ```rust
/// use aether_rust_shell::egl_api::create_browser_capsule;
///
/// let firefox = create_browser_capsule(
///     "firefox",
///     &PathBuf::from("/usr/bin/firefox"),
///     "sha256:firefox_expected_hash",
/// );
///
/// launcher.register_capsule(firefox);
/// ```
///
/// # Häufig gestellte Fragen (FAQ)
///
/// ## Q: Kann EGL Malware-Downloads verhindern?
/// A: Nein, EGL arbeitet auf Metadaten-Ebene. Es kann:
///    - Netzwerkziele blockieren (z. B. Malware-Repositories)
///    - Datei-Downloads in Sandboxes isolieren
///    Aber es kann einen Datei-Hash NICHT gegen eine globale Malware-Liste prüfen,
///    da das Cloud-Dependencies erfordert (verbietet). Lokal: Ja, wenn Hashes
///    bekannt sind.
///
/// ## Q: Warum kein Machine Learning?
/// A: Weil:
///    - ML-Modelle sind nicht deterministisch (Floating-Point-Randomness, GPU-Varianz)
///    - ML-Entscheidungen sind nicht erklärbar/auditierbar
///    - ML erfordert oft Cloud-Training (Privatsphäre-Problem)
///    - Regelbasierte Systeme sind für Sicherheit transparenter
///
/// ## Q: Kann ich Regeln zur Laufzeit ändern?
/// A: Ja, mit `launcher.add_policy_rule()` oder `launcher.policy_mut()`.
///    Änderungen gelten nur für NEW-Anfragen, nicht für laufende Prozesse.
///
/// ## Q: Was passiert mit vertrauenswürdigen Anwendungen?
/// A: Sie werden wie alle anderen behandelt:
///    - Integrity-Check vor Start
///    - Sandbox-Isolierung
///    - Netzwerk-Whitelist
///    Es gibt KEIN "vertrauenswürdiger" Modus, der EGL umgeht.
///
/// # Sicherheits-Eigenschaften
///
/// ✅ **Lokal**: Alle Entscheidungen lokal, kein Netzwerk-Zugriff für Governance
/// ✅ **Deterministisch**: Gleiche Eingabe → Gleiche Ausgabe
/// ✅ **Regelbasiert**: Menschenlesbare, auditierbare Regeln
/// ✅ **Inhaltsoblindig**: Keine Inhaltsanalyse, nur Metadaten
/// ✅ **Integritätsprüfung**: Vor dem Start viaa Aether
/// ✅ **Netzwerk-Isolierung**: Whitelist-basiert, keine Telemetrie-Domains
/// ✅ **Audit-Trail**: Nur Metadaten, lokal, nicht exportiert
///
/// # Nächste Schritte
///
/// 1. **Kapseln definieren**: Für jede Anwendung, die Sie kontrollieren möchten
/// 2. **Policies schreiben**: Welche Rechte hat jede App?
/// 3. **Tests**: Unit-Tests für Policy-Regeln
/// 4. **Deployment**: Setzen Sie GoverningLauncher in Ihre Desktop-App ein
/// 5. **Monitoring**: Prüfen Sie Audit-Logs auf unerwartete Zugriffe
///
/// # Lizenz
///
/// Dieses Modul ist Teil von Aether und unterliegt der Aether Source Available License.

// Dummy file – documentation only
