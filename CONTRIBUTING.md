# Contributing to signet-exporter

Thank you for your interest in contributing. This document outlines the development workflow.

## Development Prerequisites

- Go 1.22+
- `golangci-lint` (for linting)
- `make`

## Workflow

1. Fork the repository and create a feature branch from `main`.
2. Make your changes. Run `make test` and `make lint` before committing.
3. Write or update tests for any changed behaviour.
4. Open a pull request against `main` with a clear description of the change and its motivation.

## Code Standards

- All exported symbols must have doc comments.
- Error strings must be lowercase and not end with punctuation (Go convention).
- Use `log/slog` for all logging — no `fmt.Print` in production paths.
- Do not introduce dependencies without discussion; the dependency list is intentionally minimal.
- Security-sensitive changes (network I/O, TLS, file access) require extra care and should reference relevant RFCs or NIST controls in comments.

## Commit Messages

Use the format: `<type>: <short description>` where type is one of `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.

## Security Issues

Do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md).
