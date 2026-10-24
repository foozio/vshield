from vulnshield.remote.ssh.authentication import SshAuthCredentials, ProtectedCredentialProvider
from vulnshield.remote.ssh.platforms import PlatformType, PlatformProfile, PlatformDetector
from vulnshield.remote.ssh.collectors import (
    CommandValidator,
    SshEvidenceCollector,
    SshSystemTelemetry,
    SecurityCommandValidationError,
    VETTED_COMMAND_TEMPLATES,
)
from vulnshield.remote.ssh.client import (
    SafeSshClient,
    SshExecutionError,
    SshAuthenticationError,
    SshHostKeyError,
)

__all__ = [
    "SshAuthCredentials",
    "ProtectedCredentialProvider",
    "PlatformType",
    "PlatformProfile",
    "PlatformDetector",
    "CommandValidator",
    "SshEvidenceCollector",
    "SshSystemTelemetry",
    "SecurityCommandValidationError",
    "VETTED_COMMAND_TEMPLATES",
    "SafeSshClient",
    "SshExecutionError",
    "SshAuthenticationError",
    "SshHostKeyError",
]
