# Security policy

## Reporting a vulnerability

Email **support@securityaccelerated.com** with a description of the issue, the steps to
reproduce it, and the impact you believe it has. You will get an acknowledgement within
three business days and a status update when the issue is confirmed, fixed, or declined.

Please do not open a public GitHub issue for a security problem. Issues here are public,
and a report in one would be visible before a fix exists.

There is no bug bounty programme. Reports are credited in the release notes if you want
them to be.

## Scope

In scope:

- This repository: the API server, the `sactl` operator CLI, the migrations, and the
  GitHub Actions workflows.
- The deployed service at `https://api.securityaccelerated.com`, limited to testing with
  your own API key against domains and IP addresses you control or have permission to
  test. Server-side request forgery, authentication and authorization bypasses, rate-limit
  evasion, and information disclosure are the classes we most want to hear about.

Out of scope:

- Denial of service, volumetric testing, or anything that degrades the service for other
  users. The rate limiter is a product control, not a challenge.
- Findings in third-party data sources the API queries. Report those to the source.
- Social engineering, physical attacks, and reports that require a compromised customer
  account as a precondition.

## Supported versions

Only the version running at `https://api.securityaccelerated.com` is supported. It is the
latest `v*` tag on `main`. Earlier tags receive no fixes.

## Design notes for reviewers

The things most worth checking are documented in the repository rather than here:

- `internal/safenet` is the single outbound-dial guard in the API server. Every outbound
  HTTP client there goes through it; a new one that does not is a vulnerability. The
  `sactl` CLI talks only to the API host the operator names and uses a plain client.
- API keys are stored as SHA-256 hashes. The one plaintext exception, `provisioned_keys`,
  is described in `.claude/rules/auth-billing.md`.
- `docs/decisions.md` explains the controls that look removable and are not.
