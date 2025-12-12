{
  "dependencies": [
    "backward-cpp",
    {
      "name": "cpp-httplib",
      "default-features": false,
      "features": [
        "zlib"
      ]
    },
    {
      "name": "curl",
      "default-features": false,
      "features": [
        "ssl"
      ],
      "platform": "(windows & !uwp) | mingw"
    },
    {
      "name": "curl",
      "default-features": false,
      "features": [
        "wolfssl"
      ],
      "platform": "(uwp | !windows) & !mingw"
    },
    "fmt",
    "gtest",
    {
      "name": "libuv",
      "platform": "windows | android"
    },
    "ncnn",
    "nlohmann-json",
    {
      "name": "opencv4",
      "default-features": false,
      "features": [
        "jpeg",
        "png",
        "tiff",
        "webp"
      ]
    },
    "tesseract",
    {
      "name": "uwebsockets",
      "features": [
        "zlib"
      ]
    }
  ]
}
