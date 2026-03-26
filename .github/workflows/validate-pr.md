---
# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

description: Validate if this Pull Request meets our project criteria (kaito-tokyo/vcpkg-obs-kaito-tokyo). COPILOT_GITHUB_TOKEN needs to be configured.

"on":
  label_command:
    name: validate
    events: [pull_request]

metadata:
  author: Kaito Udagawa
  version: "1.0.0"

permissions:
  contents: read
  pull-requests: read

mcp-scripts:
  pull-request-commits:
    description: Returns a JSON Lines text that represents all the commit information of the Pull Request. Each output line contains the `sha`, `message`, and `verification` fields.
    inputs:
      prnumber:
        type: string
        required: true
        description: The number of Pull Request
    env:
      GH_TOKEN: ${{ github.token }}
    run: |
      gh api \
        "repos/$GITHUB_REPOSITORY/pulls/$INPUT_PRNUMBER/commits" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2026-03-10" \
        --paginate \
        --jq '.[] | {sha: .sha, message: .commit.message, verification: .commit.verification}' | jq -c '.'

safe-outputs:
  submit-pull-request-review:

engine:
  id: copilot
  model: gpt-5-mini

run-name: Validate PR
---

# Pull Request Validator

Validate if this Pull Request meets our project criteria (kaito-tokyo/vcpkg-obs-kaito-tokyo).

## Additional Inputs

**Pull Request Title:**

```text
${{ steps.sanitized.outputs.title }}
```

**Pull Request Body:**

```text
${{ steps.sanitized.outputs.body }}
```

## Requirements

- **Commit Signing**
  - **Tooling:** Use the pull-request-commits tool to fetch commit data of this Pull Request.
  - **Verification:** Inspect the `verification` object of every commit on this Pull Request, and verify if all commits on this Pull Request are properly signed.
  - **Context:** Refer to `<PROJECT_ROOT>/CONTRIBUTING.md` for this commit signing policy.

- **DCO (Developer’s Certificate of Origin)**
  - **Tooling:** Use the pull-request-commits tool to fetch commit data of this Pull Request.
  - **Verification:** Inspect the `message` field of every commit on this Pull Request, and verify if all commits on this Pull Request contain a valid `Signed-off-by:` trailer for DCO compliance.
  - **Context:** Refer to `<PROJECT_ROOT>/CONTRIBUTING.md` for this policy.

- **Pull Request Checklist**
  - **Verification:** Read the Pull Request text provided above, and verify if it contains the Pull Request template and all the items are checked.

## Outputs

- **Output Format**: Use Pull Request review.
- **Summary Line**: The first line of your comment MUST be a single-line summary of this validation, starting with either ✅ or 🚫.
- **Success**: If this Pull Request meets all criteria, submit an approval review, attaching this Pull Request's title and body including the checklist provided above as a code block for later reference.
- **Failure**: If this Pull Request fails to meet any criteria, submit a request-changes review that states what the problems are on this Pull Request.
