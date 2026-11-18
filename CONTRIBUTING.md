# Contributing

Thanks for helping improve System Design Primer — Agent Skill.

## Development setup

- Python 3.10 or later; no third-party Python packages are required.
- Bash for POSIX installers and integration tests.
- PowerShell 7 or Windows PowerShell 5.1 for the Windows installer test.

## Before opening a change

Run these commands from the repository root:

    python scripts/validate.py
    python -m unittest discover -s tests -v
    bash -n scripts/install.sh tests/test_install.sh
    bash tests/test_install.sh
    python tools/package.py --output-dir dist

On Windows, also run:

    .\tests\test_install.ps1

## Content quality bar

- Explain assumptions and trade-offs; avoid absolute claims where system semantics depend on implementation.
- Separate measured facts, user-provided requirements, and estimates.
- Prefer actionable review checks over generic architecture slogans.
- Keep the main SKILL.md focused; put deep reference material in references/ for progressive disclosure.
- Update references, examples, templates, tests, and changelog when behavior changes.
- Do not include secrets, private production data, vendor credentials, or unverifiable benchmark claims.

## Release process

1. Update VERSION and add a dated entry to CHANGELOG.md.
2. Run the full validation, unit tests, POSIX installer tests, and package builder locally; run the PowerShell installer test on Windows.
3. Merge the change into main only after the required CI matrix passes.
4. Create and push a version tag whose name exactly matches v<VERSION> (for example, v1.2.0).
5. The tag-triggered release workflow repeats Linux, macOS, and Windows validation before building and publishing the ZIP and SHA-256 checksum.
6. Do not move or reuse a published version tag. Publish a new patch/minor version for corrections.

Repository branch protection and immutable tag rules are GitHub repository settings, not files in this repository. Maintainers should enable pull-request/required-check rules and protect v* tags in repository settings.

## Pull requests

Include the problem, proposed change, compatibility impact, validation performed, and any migration or rollback notes. Keep changes focused and update VERSION/CHANGELOG for user-visible releases.
