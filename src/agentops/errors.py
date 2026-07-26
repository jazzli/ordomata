"""Domain-specific failures for the orchestrator."""


class AgentOpsError(Exception):
    """Base class for expected orchestrator failures."""


class ConfigurationError(AgentOpsError):
    """Configuration is invalid or incomplete."""


class BillingRouteBlocked(AgentOpsError):
    """Execution was blocked because billing was not subscription-safe."""


class LiveRunDisabled(AgentOpsError):
    """A live harness run was attempted without the explicit live gate."""


class ValidationError(AgentOpsError):
    """Structured data failed deterministic validation."""


class RunnerUnavailable(AgentOpsError):
    """A requested runner or capability is unavailable."""
