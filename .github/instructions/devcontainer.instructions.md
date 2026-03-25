---
# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

applyTo: '.devcontainer/devcontainer.json'
---

When devcontainer.json uses the dockerComposeFile property, the workspace must be mounted by using the mounts property, not like the build property. The workspaceMount property cannot be used with the dockerComposeFile property.
