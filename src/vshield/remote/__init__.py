from vshield.remote.targets import (
    TargetConfig,
    HttpProtocolConfig,
    SshProtocolConfig,
    parse_targets_file,
    TargetInventoryManager,
)
from vshield.remote.authorization import TargetAuthorizer, AuthorizationError, redact_sensitive
from vshield.remote.scheduler import ScheduleManager, ScheduleJob
from vshield.remote.correlation import CrossProtocolCorrelator
from vshield.remote.scanner import (
    RemoteAssessmentEngine,
    CancellationContext,
    AuditLogger,
)

__all__ = [
    "TargetConfig",
    "HttpProtocolConfig",
    "SshProtocolConfig",
    "parse_targets_file",
    "TargetInventoryManager",
    "TargetAuthorizer",
    "AuthorizationError",
    "redact_sensitive",
    "ScheduleManager",
    "ScheduleJob",
    "CrossProtocolCorrelator",
    "RemoteAssessmentEngine",
    "CancellationContext",
    "AuditLogger",
]
