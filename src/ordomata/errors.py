"""Domain-specific failures for the orchestrator."""


class OrdomataError(Exception):
    """Base class for expected orchestrator failures."""


class ConfigurationError(OrdomataError):
    """Configuration is invalid or incomplete."""


class BillingRouteBlocked(OrdomataError):
    """Execution was blocked because billing was not subscription-safe."""


class AuthorizationBlocked(OrdomataError):
    """Execution was blocked by a controller-owned authorization gate."""


class LiveRunDisabled(OrdomataError):
    """A live harness run was attempted without the explicit live gate."""


class ValidationError(OrdomataError):
    """Structured data failed deterministic validation."""


class RunnerUnavailable(OrdomataError):
    """A requested runner or capability is unavailable."""
