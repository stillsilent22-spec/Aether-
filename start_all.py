import subprocess
import sys
import time
import os

def run_backend():
    # Starte das Python-Backend im Hintergrund
    return subprocess.Popen([sys.executable, "start.py"])

def run_ui():
    # Starte das Rust-UI (cargo run --bin aether_iced)
    # Unter Windows muss ggf. die Umgebung angepasst werden
    return subprocess.Popen(["cargo", "run", "--bin", "aether_iced"])

if __name__ == "__main__":
    print("Starte Backend (Python)...")
    backend_proc = run_backend()
    # Warte kurz, damit das Backend initialisiert werden kann
    time.sleep(2)
    print("Starte Benutzeroberfläche (Rust/Iced)...")
    ui_proc = run_ui()

    try:
        # Warte, bis einer der Prozesse beendet wird
        while True:
            if backend_proc.poll() is not None:
                print("Backend-Prozess wurde beendet.")
                break
            if ui_proc.poll() is not None:
                print("UI-Prozess wurde beendet.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("Beende beide Prozesse...")
        backend_proc.terminate()
        ui_proc.terminate()
        backend_proc.wait()
        ui_proc.wait()
    print("Fertig.")