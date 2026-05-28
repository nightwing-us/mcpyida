# Contributing to mcpyida

Thank you for your interest in contributing to `mcpyida`.  Contributions
of all kinds are welcome: bug reports, documentation improvements, and code
patches.

---

## Code of Conduct

All interactions in this project are governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).  Please read it before participating.

---

## Development Setup

### Prerequisites

- Python 3.10 or later
- An IDA Pro installation (required at runtime for integration/e2e tests; not
  needed for lint/typecheck/unit-test work)

### Clone and install

```bash
git clone https://github.com/nightwing-us/mcpyida.git
cd mcpyida
pip install -e ".[dev]"
```

### Running the test suite

Unit tests (no IDA Pro required):

```bash
pytest tests/unit/ --tb=short
```

Integration and e2e tests require IDA Pro / idalib and are run in a CI
environment with an IDA Pro license available.

### Linting

```bash
ruff check src tests
```

### Type-checking

```bash
mypy
```

All three commands must pass before submitting a pull request.  The CI workflow
runs them automatically on every PR.

---

## DCO Sign-Off Requirement

This project uses the **Developer Certificate of Origin (DCO)** to confirm that
contributors have the right to submit their contributions under the project
license.

Every commit in your pull request must carry a `Signed-off-by:` trailer:

```
Signed-off-by: Jane Doe <jane@example.com>
```

The name and email must match your real identity.  Add it automatically with
the `-s` flag:

```bash
git commit -s -m "fix: correct handling of null MCP response"
```

By signing off you certify that you agree to the terms at
<https://developercertificate.org/>.  The full DCO text is reproduced there;
the core statement is: you wrote the code (or have the right to submit it),
and you grant the project the right to use it under the Apache-2.0 license.

**DCO enforcement:** A status check on every pull request verifies that all
commits are signed off.  Pull requests without signed-off commits cannot be
merged.

---

## Pull Request Process

### Branch naming

Use a short, descriptive branch name prefixed with the change type:

```
fix/headless-port-assignment
feat/add-callgraph-tool
docs/update-installation-guide
chore/bump-ruff-version
```

### Commit messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/).
Please format commit messages as:

```
<type>(<optional scope>): <short description>

<optional body>

Signed-off-by: Jane Doe <jane@example.com>
```

Common types: `fix`, `feat`, `docs`, `chore`, `ci`, `refactor`, `test`.

### Before pushing

Run the full local check suite:

```bash
ruff check src tests
mypy
pytest tests/unit/ --tb=short
```

### Opening the PR

- Target the `main` branch.
- Fill in the PR description with what changed and why.
- Link any related issues.
- Ensure all CI checks pass.

### How your contribution lands

Maintainers review and approve pull requests on GitHub, then integrate
approved commits via cherry-pick rather than the GitHub "Merge" button.
As a result your PR will be **closed** (not merged via the button) once
the change has landed on `main`, and the maintainer will post a comment
such as:

> Landed in v1.2.3 — commit abc1234.  Thanks!

Your change will appear in the next release.  This is intentional and
does not mean your contribution was rejected.

---

## Code Style

- **Formatter:** [ruff](https://docs.astral.sh/ruff/) with the configuration in
  `pyproject.toml` (`[tool.ruff]`).
- **Type-checking:** [mypy](https://mypy.readthedocs.io/) in gradual mode
  (not `--strict`).  Annotations are encouraged but not required everywhere:
  IDA Pro API modules are `Any`-typed via `[[tool.mypy.overrides]]` stubs (the
  IDA Python API has no public type stubs; idalib is dlopen-loaded at runtime),
  and `warn_return_any` is intentionally disabled to avoid ~80 false-positive
  ignores on IDA wrapper return sites.  Add annotations to new code and tighten
  existing code incrementally.  If you use `Any` outside of IDA-API call sites,
  add an inline comment explaining why and expect discussion in review.
- **Import ordering:** ruff handles import ordering as part of formatting
  (config in `pyproject.toml` `[tool.ruff]`).
- **Line length:** 120 characters (prose in docstrings: 80 characters).
- **String quotes:** single quotes preferred (ruff enforces this).

When in doubt, run `ruff check --fix` and `ruff format` to auto-correct most
style issues before committing.

---

## Reporting Bugs

Open an issue on [GitHub Issues](https://github.com/nightwing-us/mcpyida/issues).

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

---

## Questions

Feel free to open a GitHub Discussion or comment on a relevant issue.
