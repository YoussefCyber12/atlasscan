# Contributing to AtlasScan

Thanks for taking the time to contribute.

## Ground rules

* Only add checks that are safe to run against a normal application.
* No checks that could destroy data, brute-force real credentials, or hammer a target.
  (The JWT module only tries a fixed list of well-known placeholder secrets.)
* Every new module needs a test against the local test server in `tests/conftest.py`.
* Keep dependencies minimal. Standard library first.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
ruff check .
```

## Adding a module

1. Create `atlasscan/modules/my_check.py` with a class exposing `name`, `description`, and
   `run(ctx) -> list[Finding]`.
2. Register it in `atlasscan/modules/__init__.py`.
3. Add it to `DEFAULT_MODULES` if it should run in a normal scan.
4. Add a vulnerable endpoint to the test server and a test in `tests/`.
5. Update the module table in `README.md`.

## Pull requests

* Keep commits focused; one feature/fix per PR.
* Describe the vulnerability class and how the check avoids false positives.
* `pytest` and `ruff check .` must pass (CI enforces both).
