# Security Notes

## Scope

Aether is a local desktop system. It is hardened for local use, audit, and controlled publication, but it is not a formally verified secure platform.

## Current protections

- Passwords are not stored in plaintext.
- Login state is separated from runtime session state.
- Local chain entries are inert and sanitized before append.
- AE/Vault candidates are filtered, quarantined, and fail closed on unsafe specs.
- Chat-sync identities are separated from login credentials.
- Local sync secrets are protected at rest before being written to the user database.
- Critical integrity tamper in `PROD` mode can block startup instead of falling through.

## Current limits

- Secrets still exist in process memory while the app is running.
- This project has not undergone an external security audit.
- The relay/chat sync path is encrypted in transport/application terms, but it is not a full zero-trust messaging platform.
- Windows-local secret protection is the primary target; cross-platform hardening is weaker.

## Public repository checklist

Before publishing:

- Do not commit local SQLite databases.
- Do not commit generated DNA vault files from runtime sessions.
- Do not commit `dist/`, `build/`, startup logs, reject logs, or fingerprint ledgers.
- Do not commit private corpora, chat dumps, relay secrets, or exported sync records.
- Recheck README/WHITEPAPER for personal or operational details you do not want public.

## Recommended next hardening steps

- Move more local secrets into OS-backed secret storage.
- Add explicit export/import permission gates in the GUI.
- Add integrity tests for registry migrations and sync paths.
- Perform a manual pre-release review before every public push.
