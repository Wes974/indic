# Security Policy

## Reporting a Vulnerability

indic is a tool for **defensive** security research. If you discover a
security vulnerability in indic itself, please **do not** open a public issue.

Instead, use GitHub's [private vulnerability reporting](https://github.com/Wes974/indic/security/advisories/new)
— this opens a confidential draft advisory visible only to maintainers.

I'll acknowledge within 48 hours and aim for a fix within 7 days.

## Scope

- The indic binary and its dependencies
- The Docker image
- The embedded web UI

**Out of scope**: misconfigurations of your own deployment, third-party API key
leaks, vulnerabilities in upstream enricher APIs.

## Supported Versions

| Version  | Supported          |
|----------|--------------------|
| `latest` | :white_check_mark: |
| `< latest` | :x:             |
