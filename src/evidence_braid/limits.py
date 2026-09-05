"""Explicit resource ceilings for untrusted input documents.

Each input dimension has a default the adapters apply when a caller says
nothing and a compiled ``MAX_`` ceiling. A caller may tighten a limit for a
particular feed; it can never raise one above its ceiling. Oversized input is
refused with a domain error rather than truncated, so a decision is never made
from a partially read stream.
"""

DEFAULT_MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_POLICY_BYTES = 16 * 1024 * 1024

DEFAULT_MAX_EVENT_FILE_BYTES = 64 * 1024 * 1024
MAX_EVENT_FILE_BYTES = 256 * 1024 * 1024

DEFAULT_MAX_LINE_BYTES = 1 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024 * 1024
