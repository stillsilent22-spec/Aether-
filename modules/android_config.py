import logging
logger = logging.getLogger(__name__)
"""Android platform detector and config."""
import os, sys

def is_android() -> bool:
    return "ANDROID_ROOT" in os.environ or os.path.exists("/system/build.prop")

def android_swarm_config() -> dict:
    return {
        "swarm_enabled": True,
        "consent_required": False,
        "ui_enabled": False,
        "worker_compute_enabled": True,
        "beacon_relay_enabled": True,
    }

def apply_android_config() -> None:
    if is_android():
        os.environ["AETHER_PLATFORM"] = "android"
