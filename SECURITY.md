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

## Process isolation limitation

The build-provenance verifier bounds GitHub CLI execution time and captured output. On POSIX, it starts the CLI in a new session and terminates that process group during cleanup. On Windows, it assigns the already-created CLI process to a kill-on-close Job Object. Because the standard `subprocess.Popen` path creates the process before that assignment, there is a short startup window in which a descendant created by the CLI may not belong to the Job Object. Descendants created after successful assignment are covered; descendants created before assignment are not guaranteed to be contained.

Do not treat this Windows Job Object integration as a race-free sandbox for hostile commands. Environments that require strict process-tree containment should run the verifier inside an independently enforced isolation boundary. Eliminating this window requires a native `CreateProcessW`/`STARTUPINFOEX` launch path with creation-time Job Object association and dedicated lifecycle tests; it is not provided by the current `Popen` implementation.
