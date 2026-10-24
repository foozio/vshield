"""Configuration, environment variables, and backward-compatible path resolution for vShield."""

from __future__ import annotations

import os
import warnings
from pathlib import Path


def get_data_dir() -> str:
    """
    Returns the resolved data directory for vShield.
    Supports VSHIELD_DATA_DIR, with backward-compatible fallback to VULNSHIELD_DATA_DIR.
    """
    if "VSHIELD_DATA_DIR" in os.environ:
        return os.environ["VSHIELD_DATA_DIR"]

    if "VULNSHIELD_DATA_DIR" in os.environ:
        warnings.warn(
            "VULNSHIELD_DATA_DIR environment variable is deprecated. Please migrate to VSHIELD_DATA_DIR.",
            DeprecationWarning,
            stacklevel=2,
        )
        return os.environ["VULNSHIELD_DATA_DIR"]

    # Try ~/.vshield, or fallback to existing ~/.vulnshield if present, otherwise create ~/.vshield
    vshield_home = Path(os.path.expanduser("~/.vshield"))
    vulnshield_home = Path(os.path.expanduser("~/.vulnshield"))

    if not vshield_home.exists() and vulnshield_home.exists():
        return str(vulnshield_home)

    try:
        vshield_home.mkdir(parents=True, exist_ok=True)
        return str(vshield_home)
    except Exception:
        # Fallback to local workspace if home directory is restricted
        return os.path.join(os.getcwd(), ".vshield")


def get_ssh_password_env() -> str:
    """Returns the name of the environment variable for SSH passwords."""
    if "VSHIELD_SSH_PASSWORD" in os.environ:
        return "VSHIELD_SSH_PASSWORD"
    if "VULNSHIELD_SSH_PASSWORD" in os.environ:
        warnings.warn(
            "VULNSHIELD_SSH_PASSWORD environment variable is deprecated. Please migrate to VSHIELD_SSH_PASSWORD.",
            DeprecationWarning,
            stacklevel=2,
        )
        return "VULNSHIELD_SSH_PASSWORD"
    return "VSHIELD_SSH_PASSWORD"
