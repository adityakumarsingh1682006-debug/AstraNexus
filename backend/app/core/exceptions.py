"""
AstraNexus Custom Domain Exceptions
"""

class AstraBaseException(Exception):
    """Base exception for all AstraNexus custom domain exceptions."""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR"):
        self.message = message
        self.code = code
        super().__init__(self.message)


class SSRFSecurityViolation(AstraBaseException):
    """Raised when an outbound scan target resolves to private, loopback, or forbidden IP."""
    def __init__(self, message: str = "Target IP address violates SSRF security boundaries"):
        super().__init__(message=message, code="SSRF_VIOLATION")


class TargetResolutionError(AstraBaseException):
    """Raised when domain cannot be resolved via DNS."""
    def __init__(self, message: str = "Failed to resolve target hostname"):
        super().__init__(message=message, code="DNS_RESOLUTION_FAILURE")


class ScanTimeoutError(AstraBaseException):
    """Raised when an inspection times out."""
    def __init__(self, message: str = "Scan operation timed out"):
        super().__init__(message=message, code="SCAN_TIMEOUT")


class TargetPayloadTooLargeError(AstraBaseException):
    """Raised when remote response exceeds maximum allowed size."""
    def __init__(self, message: str = "Remote target response exceeded maximum inspection size"):
        super().__init__(message=message, code="PAYLOAD_TOO_LARGE")
