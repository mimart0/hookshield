# Security Policy

HookShield exists to help keep AI coding session context local and reviewable. Please handle security reports with that same care.

## Supported Versions

HookShield is pre-1.0. Security fixes target the current `main` branch unless a release branch exists later.

## Reporting a Vulnerability

Please do not open a public issue for vulnerabilities that could expose prompts, transcripts, tool calls, local files, credentials, or bypass strict-mode protections.

Report privately by opening a GitHub security advisory for this repository, or contact the maintainer directly if you already have an established private channel.

Include:

- a concise description of the issue
- affected command or workflow
- reproduction steps using sanitized data
- expected impact
- OS, Node version, and HookShield commit

## What Counts

Useful security reports include:

- private session artifacts being written somewhere unexpected
- strict-mode network or file enforcement bypasses
- failure to restore virtualized hooks/configs
- unsafe handling of encryption keys
- accidental inclusion of private artifacts in git history
- command injection, path traversal, or unsafe file permission behavior

## Public Disclosure

Please give the maintainer time to reproduce and patch the issue before public disclosure.
