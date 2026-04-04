from __future__ import annotations

"""Legacy compatibility stub for the removed desktop GUI.

The project uses the Rust/Iced shell as the primary UI.
This module is intentionally kept to avoid hard import failures in
legacy scripts that still import `modules.gui`.
"""


class AetherGUI:
    """Compatibility placeholder.

    Legacy callers can still instantiate this class, but `run()` explains
    that the old frontend was removed.
    """

    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    def run(self) -> None:
        raise RuntimeError(
            "Legacy GUI was removed. Start the Rust shell via `cargo run --bin aether_iced`."
        )


VeiraGUI = AetherGUI
