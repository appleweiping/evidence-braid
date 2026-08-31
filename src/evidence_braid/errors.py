"""Domain-specific errors with stable, user-facing messages."""


class EvidenceBraidError(Exception):
    """Base class for errors a caller can safely present to an operator."""


class ValidationError(EvidenceBraidError, ValueError):
    """Raised when an event or policy violates the public schema."""


class InputFormatError(EvidenceBraidError):
    """Raised when JSON or JSONL input cannot be decoded."""
