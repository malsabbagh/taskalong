# Dependency inventory

No dependency source or wheel is vendored in TaskAlong's distribution. Runtime,
optional-review and locked development dependencies are installed separately.
The current lock/qualification inventory records:

| Component | Version | Declared/included license |
| --- | --- | --- |
| jsonschema | 4.26.0 | MIT |
| attrs | 26.1.0 | MIT |
| jsonschema-specifications | 2025.9.1 | MIT |
| referencing | 0.37.0 | MIT |
| rpds-py | 2026.6.3 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| ReviewSensei (optional, separately installed) | 0.8.8 | MIT |
| build | 1.6.1 | MIT |
| pyproject_hooks | 1.2.0 | MIT (included license file) |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| setuptools | 84.0.0 | MIT |
| certifi | 2026.7.22 | MPL-2.0 (included license file) |

This table is an inventory, not a claim to relicense dependencies or independent
legal clearance. Retain upstream license/attribution requirements when separately
redistributing dependencies. No vendor SDK implementation or private source is
adapted into the package. GitHub Actions are external pinned workflow uses, not
vendored package code. TaskAlong itself uses the [MIT License](LICENSE); dependency licenses are unchanged.
