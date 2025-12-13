# vcpkg-obs-kaito-tokyo

A custom [vcpkg](https://vcpkg.io/) registry providing custom ports for various C++ libraries.

## Overview

This repository serves as a vcpkg registry that hosts custom or modified versions of several packages. It is designed to work alongside the official vcpkg registry.

## Available Ports

This registry provides the following packages:

- **kaldi** - Speech recognition toolkit
- **libpng** - PNG image library
- **openfst** - Finite-state transducers library
- **tesseract** - OCR (Optical Character Recognition) engine
- **vosk** - Offline speech recognition API
- **wolfssl** - Embedded SSL/TLS library

## Binary Cache for OBS

The binary caches available in this repository are optimized for modern OBS (Open Broadcaster Software). Developers can easily link libraries from this registry to their OBS plugins, streamlining the plugin development process with pre-built, compatible binaries.

### Using the Binary Cache

To use the binary cache from this repository in **GitHub Actions**, set the `VCPKG_BINARY_SOURCES` environment variable:

```bash
export VCPKG_BINARY_SOURCES="clear;http,https://vcpkg-obs.kaito.tokyo/{name}/{version}/{sha}"
```

This will configure vcpkg to download pre-built binaries from our cache, significantly speeding up your build process.

**Note:** This binary cache is only accessible within GitHub Actions workflows.

## Usage

To use this registry in your project, add the following to your `vcpkg-configuration.json`:

```json
{
  "default-registry": {
    "kind": "git",
    "baseline": "<baseline-commit-hash>",
    "repository": "https://github.com/microsoft/vcpkg"
  },
  "registries": [
    {
      "kind": "git",
      "baseline": "<baseline-commit-hash>",
      "repository": "https://github.com/kaito-tokyo/vcpkg-obs-kaito-tokyo",
      "packages": [
        "libpng",
        "kaldi",
        "openfst",
        "tesseract",
        "vosk",
        "wolfssl"
      ]
    }
  ]
}
```

Replace `<baseline-commit-hash>` with the appropriate commit hash from this repository.

## Infrastructure

This registry leverages Cloudflare-based infrastructure to provide enterprise-level security and almost-zero running cost:

- **Cloudflare Workers**: Serverless functions handling authentication and binary cache operations
  - `apiauth`: JWT-based authentication service for secure API access
  - `readwrite`: Binary cache management with R2 presigned URLs
- **Cloudflare R2**: Object storage for vcpkg binary cache with zero egress fees
- **Edge Computing**: Global distribution through Cloudflare's edge network for low-latency access

The infrastructure uses JWT tokens with EdDSA signatures for secure authentication, and presigned URLs for direct R2 access, minimizing serverless compute costs while maintaining high security standards.

## Development

### Adding Versions

After modifying a port, use the provided script to add versions:

```bash
./add-versions.bash
```

This script will automatically update the version database for all packages in the `ports/` directory.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (C) 2025 Kaito Udagawa
