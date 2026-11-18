# Contributing

Thanks for helping improve System Design Primer — Agent Skill.

## Development setup

- Python 3.10 or later; no third-party Python packages are required.
- Bash for the POSIX installer and integration test.
- PowerShell 7 or Windows PowerShell 5.1 for the Windows installer test.

## Before opening a change

Run these commands from the repository root:

    python scripts/validate.py
    python -m unittest discover -s tests -v
    bash -n scripts/install.sh
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

## Pull requests

Include the problem, proposed change, compatibility impact, validation performed, and any migration or rollback notes. Keep changes focused and update VERSION/CHANGELOG for user-visible releases.
