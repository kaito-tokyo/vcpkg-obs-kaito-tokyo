---
# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

applyTo: "**/*.{yml,yaml}"
---

# Development Guidelines for GitHub Actions Workflow

## Style guides

- **Name identifies unique step**: Every step that has the same name must have the same step definition across all workflows.
- **Prefer single quotes for environment variables**: Prefer to quote the value of environment variables on run steps using single quotes. This style has good consistency when we handle backslashes in Windows paths. You can switch to use double quotes or write values without quoting only if single quotes result in a messy syntax.
- **Enforce error-prone bash**: Always use `bash --noprofile --norc -euo pipefail -O nullglob {0}` for shell on run steps.
- **Multi-line syntax for run**: Always use multi-line syntax for the content of run to keep the style consistent.

## Preinstalled Softwares on GitHub Actions Runner Images

- **The command `xcbeautify`** is preinstalled on the runner `macos-15`.
- **The command `jq`** is preinstalled on all the runner including `windows-2022`, `macos-15`, `ubuntu-slim`, and `ubuntu-24.04`.
- **The command `yamllint`** is preinstalled on the runner `ubuntu-24.04`.

## Inputs for the action `actions/setup-python`

- **python-version-file**: File containing the Python version to use. Example: .python-version
- **pip-install**: Used to specify the packages to install with pip after setting up Python. Can be a requirements file or package names.
