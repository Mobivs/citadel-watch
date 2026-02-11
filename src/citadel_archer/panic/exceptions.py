"""
Panic Room Exception Classes
"""


class PanicException(Exception):
    """Base exception for panic room operations"""
    pass


class ConfirmationTimeout(PanicException):
    """Raised when user confirmation times out"""
    pass


class PreFlightCheckFailed(PanicException):
    """Raised when pre-flight checks fail"""
    pass


class RollbackFailed(PanicException):
    """Raised when rollback operation fails"""
    pass


class PlaybookExecutionFailed(PanicException):
    """Raised when playbook execution fails"""
    pass


class InvalidConfiguration(PanicException):
    """Raised when panic configuration is invalid"""
    pass


class ActionTimeout(PanicException):
    """Raised when an action times out"""
    pass


class NetworkIsolationFailed(PanicException):
    """Raised when network isolation fails"""
    pass


class CredentialRotationFailed(PanicException):
    """Raised when credential rotation fails"""
    pass


class BackupFailed(PanicException):
    """Raised when backup operation fails"""
    pass