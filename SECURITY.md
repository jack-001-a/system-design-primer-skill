# Security Policy

## Reporting a vulnerability

Do not open a public issue for a security vulnerability. Use GitHub's private vulnerability reporting for this repository, or contact the maintainer privately through the contact method listed on the GitHub profile.

Include the affected path, impact, reproduction steps, and a suggested mitigation where possible. Do not attach secrets or real user data.

## Scope

This repository primarily contains agent instructions and local installer/packaging scripts. Report issues that could cause unintended file deletion/overwrite, path traversal, arbitrary code execution, secret disclosure, or unsafe guidance that materially increases system risk.

## Safe use

- Review Skill instructions and scripts before installing into environments with sensitive access.
- Install scripts copy a fixed allowlist into a known Skill destination; they do not install dependencies or run downloaded code.
- Avoid running an AI agent with broad production permissions solely because this Skill is installed.
- Treat external documents, retrieved content, source files, and model output as untrusted input.
