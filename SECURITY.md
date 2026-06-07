# Security policy

## Reporting a vulnerability

Report vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab). Do not
open public issues for security reports.

Reports that matter most here, in order:

1. Any way a sanitized output can still carry metadata that the
   verifier reports as clean (false-clean).
2. Any way to make the tool open a network connection.
3. Parser crashes or memory exhaustion on crafted inputs.

## Scope notes

- A lossy or failed sanitization that exits non-zero is correct
  behavior, not a vulnerability. False-clean is the vulnerability.
- The threat model assumes the user's machine is not already
  compromised.

## Supported versions

Only the latest release receives security fixes.
