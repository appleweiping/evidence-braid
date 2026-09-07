# Security Policy

## Supported versions

Security updates are provided for the latest released minor version.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature instead of a public
issue. Include affected versions, a minimal reproduction, impact, and any known
workaround. Do not include real secrets or sensitive evidence.

You should receive an acknowledgement within seven days. Maintainers will
coordinate validation, a fix, a release, and disclosure timing. Please allow a
reasonable remediation window before public disclosure.

## Deployment guidance

Evidence Braid does not provide authentication, authorization, storage,
signatures, or rate limiting. Deploying applications must supply those controls.
Treat policies and evidence as untrusted input, cap file and line sizes before
calling the library, retain immutable originals when auditability matters, and
serve generated reports with an appropriate Content Security Policy.

The built-in adapters reject duplicate JSON object keys, non-standard or
non-finite numbers (including overflowing exponents), invalid UTF-8, and text
that cannot be represented safely in the standalone XML/HTML reports. These
checks reduce ambiguity; they are not a substitute for deployment-level byte,
nesting-depth, or event-count limits.
CLI domain errors escape terminal control characters and text unsupported by
the active stderr encoding.
Event attributes have defensive 64-level nesting and 1,000,000-value bounds, but applications
should set substantially smaller domain-appropriate byte and complexity limits.
Migration-report note sequences are independently capped at 100,000 entries and
are deeply snapshotted before they cross the public model boundary.
Integers accepted by public models are limited to CPython's stable 640-digit
conversion-check threshold (with the same explicit fallback on other runtimes),
so accepted Python API values cannot later fail solely because an administrator
lowered Python's configurable integer-string safety cap.

The result digest is not a signature and must not be used as proof of origin.

The bundled baselines and metrics accept in-memory validated models and mappings; callers remain
responsible for byte, event-count, and concurrency limits around evaluation jobs. Synthetic
benchmark results are not security testing and should not be used to infer denial-of-service
resistance on deployment hardware.
