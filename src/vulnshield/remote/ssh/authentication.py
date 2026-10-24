"""SSH authentication methods and protected credential management."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from vulnshield.remote.authorization import redact_sensitive


@dataclass
class SshAuthCredentials:
    username: str
    identity_file: Optional[str] = None
    use_agent: bool = True
    certificate_file: Optional[str] = None
    password: Optional[str] = None  # Protected in-memory only

    def validate(self) -> None:
        if not self.username:
            raise ValueError("SSH username cannot be empty.")
        if self.identity_file and not os.path.exists(os.path.expanduser(self.identity_file)):
            raise FileNotFoundError(f"SSH identity file '{self.identity_file}' does not exist.")
        if self.certificate_file and not os.path.exists(os.path.expanduser(self.certificate_file)):
            raise FileNotFoundError(f"SSH certificate file '{self.certificate_file}' does not exist.")

    def __repr__(self) -> str:
        # Prevent credential leakage in logs
        return (
            f"SshAuthCredentials(username='{self.username}', "
            f"identity_file='{self.identity_file}', "
            f"use_agent={self.use_agent}, "
            f"has_cert={bool(self.certificate_file)}, "
            f"has_password={bool(self.password)})"
        )


class ProtectedCredentialProvider:
    """Manages secure retrieval of credentials without logging plaintext secrets."""

    @staticmethod
    def get_password_from_env(env_var_name: str = "VULNSHIELD_SSH_PASSWORD") -> Optional[str]:
        return os.environ.get(env_var_name)

    @staticmethod
    def sanitize_log(msg: str) -> str:
        return redact_sensitive(msg)
