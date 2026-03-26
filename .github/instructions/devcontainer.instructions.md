---
# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

applyTo: ".devcontainer/devcontainer.json"
---

When devcontainer.json uses the dockerComposeFile property, the workspace must be mounted using the mounts property, rather than configured via the build property. The workspaceMount property cannot be used with the dockerComposeFile property.
