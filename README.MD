# pe-classifier (C++)

A PE analysis tool via C++ that extracts headers, sections, imports from PE-file with entropy analysis and feature exctraction


## Features

- **Portable Executable parsing** - DOS, NT, Optional Headers, Sections, Imports.
- **Entropy analysis** - Shannon entropy per section (packer detection).
- **Feature exctraction** - weighted entropy, strings density, log size for a ML training.
- **Ordinal imports** - handles both name-based and ordinal-based imports
- **No external dependencies** - only C++ standart library and WinAPI constants

## Project Structure

```
pe-classifier/
├── include/
│   ├── PeFile.hpp          # RawFile: file loading + RAII
│   ├── PeParser.hpp        # PeParser: parsing logic + PeInfo struct
│   └── Features.hpp        # FeatureVector: feature extraction
├── src/
│   ├── PeFile.cpp          # RawFile implementation
│   ├── PeParser.cpp        # PeParser implementation
│   ├── Features.cpp        # Feature extraction
│   └── main.cpp            # CLI entry point
├── .gitignore
├── build.bat
└── README.md
```

## Requirements

- **Windows 10/11**
- **MSVC 2022**
- **C++17** compiler

## Build

### With build.bat

```cmd
build.bat
```

### Manually

```Native Tools Command Prompt for VS 2022
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## Usage

```cmd
pe-classifier.exe <path_to_pe>
```

## How It Works

### 1. File Loading — RAII

`RawFile` owns `std::vector<uint8_t>`. Move-only (no copy), memory freed
automatically via destructor. No manual `HeapFree`, no leaks.

### 2. Parsing — `std::optional` + Templates

`PeParser::parse()` returns `std::optional<PeInfo>` — no exceptions in public API.
Structs are read via `readAt<T>(offset)` template with bounds checking.

### 3. Entropy — Packer Detection

Shannon entropy per section:
- `H ≈ 8.0` → random/encrypted/packed
- `H ≈ 4.0–6.0` → normal code/data
- `H ≈ 0.0` → zeros/patterns

Sections with `H > 7.0` are likely packed or encrypted.

### 4. Feature Extraction

Three numerical features per PE file (inputs for a future classifier, not ML itself):
