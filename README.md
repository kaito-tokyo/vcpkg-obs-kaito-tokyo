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

## Development

### Adding Versions

After modifying a port, use the provided script to add versions:

```bash
./add-versions.bash
```

This script will automatically update the version database for all packages in the `ports/` directory.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 kaito.tokyo
