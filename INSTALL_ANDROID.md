# INSTALL_ANDROID.md — Aether für Android

**Anleitung zur Installation und Nutzung von Aether auf Android-Geräten.**

---

## Anforderungen

- Android 5.0 (API 21) oder neuer
- ARM64 oder ARMv7 (32-bit)
- Speicher: 48 MB APK + ~80 MB laufender Heap
- Internet-Berechtigung (Yggdrasil Overlay)
- Optional: WLAN (LAN-Discovery auf Port 7386)

Kein Python, kein Termux, keine root-Rechte erforderlich.

---

## APK-Build (aus Quellcode)

### Voraussetzungen (Build-Maschine)

```bash
# JDK 17
sudo apt install openjdk-17-jdk

# Android SDK (Command-Line Tools)
mkdir ~/android-sdk
cd ~/android-sdk
wget https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip commandlinetools-*.zip
./cmdline-tools/bin/sdkmanager --install "platforms;android-34" "build-tools;34.0.0" "ndk;26.1.10909125"

# Rust cross-compilation target
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
```

### Umgebungsvariablen

```bash
export ANDROID_HOME=~/android-sdk
export NDK_HOME=~/android-sdk/ndk/26.1.10909125
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/bin:$ANDROID_HOME/platform-tools
```

### Rust-Core kompilieren (JNI)

```bash
cd aether-delta-engine

# ARM64 (moderne Geräte)
cargo build --target aarch64-linux-android --release --lib

# ARMv7 (ältere Geräte, optional)
cargo build --target armv7-linux-androideabi --release --lib
```

Die resultierenden `.so`-Dateien aus `target/<target>/release/libaether_core.so`
in `android/app/src/main/jniLibs/<ABI>/` kopieren.

### Android-Projekt bauen

```bash
cd android/
./gradlew assembleRelease
```

APK liegt in: `android/app/build/outputs/apk/release/aether-delta-engine.apk`

---

## Sideload-Installation

1. **USB-Debugging aktivieren:**
   ```
   Einstellungen → Über das Telefon → 7× auf Build-Nummer tippen
   → Entwickleroptionen → USB-Debugging: AN
   ```

2. **APK installieren:**
   ```bash
   adb install aether-delta-engine.apk
   ```

3. Alternativ APK auf das Gerät übertragen und direkt tippen.
   "Unbekannte Quellen" muss erlaubt sein.

---

## Ersten Start

1. App öffnen → Consent-Dialog erscheint
2. Swarm-Teilnahme bestätigen (Pflicht für Netzwerk-Features)
3. Vault-Initialisierung startet automatisch (~10 s)
4. Yggdrasil Overlay wird automatisch konfiguriert

---

## LAN-Discovery

Aether sendet und empfängt UDP-Beacons auf **Port 7386**.
Bei WLAN-Verbindung werden andere Aether-Knoten im lokalen Netz automatisch erkannt.
Kein Router-Setup, kein Port-Forwarding nötig.

---

## Berechtigungen

| Berechtigung | Grund |
|--------------|-------|
| INTERNET | Yggdrasil Overlay Netzwerk |
| ACCESS_WIFI_STATE | LAN-Discovery |
| ACCESS_NETWORK_STATE | Netzwerk-Statusanzeige |
| RECEIVE_BOOT_COMPLETED | Optionaler Autostart |

Keine Kamera, kein Mikrofon, kein Standort, keine Kontakte.

---

## Ressourcennutzung (Benchmark, Pixel 7)

| Zustand | CPU | RAM | Akku/h |
|---------|-----|-----|--------|
| Leerlauf | <1 % | ~48 MB | ~0.5 % |
| Aktive Analyse | 8–15 % | ~120 MB | ~2 % |
| Vault-Training | 30–60 % | ~180 MB | ~5 % |

---

## Datenspeicherung

Alle Vault-Daten und Anker werden lokal gespeichert:

```
/data/data/org.aether.delta/files/vault/       ← GP-Bäume
/data/data/org.aether.delta/files/anchors/     ← Strukturell-Anker
/data/data/org.aether.delta/files/data/        ← Cascade-Ergebnisse
```

Keine Cloud-Synchronisation. Session-Keys werden nur im RAM gehalten
und bei App-Ende sicher gelöscht.

---

## Deinstallation

```bash
adb uninstall org.aether.delta
```

Oder: Einstellungen → Apps → Aether → Deinstallieren.
Alle lokalen Daten werden gelöscht.

---

## Bekannte Einschränkungen (Android)

- Rust UI (iced) läuft **nicht** auf Android — die native Kotlin-UI wird verwendet
- Background-Vault-Training ist auf Android 12+ durch Batterieoptimierung limitiert
  (Workaround: Batterieoptimierung für Aether deaktivieren)
- DNS-over-HTTPS innerhalb Yggdrasil erfordert API 29+

---

*Aether Delta Engine — AGPL-3.0*
