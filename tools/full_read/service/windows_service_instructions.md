# Aether Swarm on Windows (Service Setup)

This guide runs the swarm agent as a Windows Service using NSSM.

## 1. Prerequisites

- Python 3.9+ installed
- Project path available (example: C:\\aether_final)
- Dependencies installed:

```powershell
pip install -r requirements.txt
```

- NSSM installed (https://nssm.cc/download)

## 2. Install service

Open PowerShell as Administrator and run:

```powershell
$nssm = "C:\\tools\\nssm\\win64\\nssm.exe"
$root = "C:\\aether_final"

& $nssm install AetherSwarm "C:\\Users\\Public\\AppData\\Local\\Programs\\Python\\Python39\\python.exe" "-m modules.swarm_agent"
& $nssm set AetherSwarm AppDirectory $root
& $nssm set AetherSwarm AppStdout "$root\\logs\\swarm_service.out.log"
& $nssm set AetherSwarm AppStderr "$root\\logs\\swarm_service.err.log"
& $nssm set AetherSwarm Start SERVICE_AUTO_START
& $nssm start AetherSwarm
```

## 3. Verify status

```powershell
Get-Service AetherSwarm
Get-Content logs\\swarm_service.out.log -Tail 80
```

## 4. Stop / restart / remove

```powershell
Stop-Service AetherSwarm
Restart-Service AetherSwarm

# Remove (NSSM)
& $nssm stop AetherSwarm
& $nssm remove AetherSwarm confirm
```

## Notes

- Swarm mode activation is still consent-gated.
- Raw frames are not persisted; only metrics and fingerprints are stored.
- P2P is opt-in and disabled by default.
