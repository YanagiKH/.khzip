# Security Policy

## Supported versions

Only the latest release receives security fixes during the pre-1.0 period.

## Reporting a vulnerability

Do not open a public issue for suspected vulnerabilities involving cryptography, key handling, path traversal, parser memory/resource exhaustion, archive authenticity, or unsafe extraction.

Use GitHub's private vulnerability reporting feature for this repository. Include:

- affected version or commit
- operating system and architecture
- minimal reproduction or malformed test archive
- expected and actual behavior
- impact assessment
- whether public disclosure is already planned

Do not include real passwords, device keys, private filenames, or confidential archives.

## Response process

A report will be triaged for reproducibility, affected versions, severity, and safe remediation. Fixes should include a regression test and, when format behavior changes, explicit compatibility notes.

## Cryptographic status

The project has not completed an independent cryptographic audit. The design uses established primitives but implementation defects remain possible. Do not market pre-1.0 releases as independently audited or formally verified.
