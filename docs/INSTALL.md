# Detailed Installation Guide

This guide provides comprehensive instructions for installing the Quantum Encryptor application on different operating systems.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git (for cloning the repository)
- C/C++ compiler (for liboqs)
- CMake (for building liboqs)

## Installing Dependencies

### 1. Install liboqs (Open Quantum Safe Library)

liboqs is the core library that provides implementations of quantum-resistant cryptographic algorithms.

#### Ubuntu/Debian

```bash
# Install build tools
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build

# Clone liboqs repository
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Create build directory
mkdir build && cd build

# Configure and build
cmake -GNinja ..
ninja

# Install system-wide
sudo ninja install

# Update dynamic linker
sudo ldconfig
```

#### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install build tools
brew install cmake ninja

# Clone liboqs repository
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Create build directory
mkdir build && cd build

# Configure and build
cmake -GNinja ..
ninja

# Install system-wide
sudo ninja install
```

#### Windows

1. Install Visual Studio 2019 or later with C++ development tools.
2. Install CMake from https://cmake.org/download/
3. Open a Developer Command Prompt for VS and run:

```cmd
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build
cd build
cmake -A x64 ..
cmake --build . --config Release
cmake --install . --config Release
```

### 2. Install Python Dependencies

After installing liboqs, you need to install the Python dependencies.

```bash
pip install -r requirements.txt
```

Or install the package in development mode:

```bash
pip install -e .
```

## Troubleshooting

### Common Issues

#### Library Not Found Error

If you see an error like `ImportError: Library not found: 'liboqs'`, this means the dynamic linker cannot find the liboqs library.

**Solution:**

On Linux:
```bash
sudo ldconfig
# Or export the library path manually
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
```

On macOS:
```bash
export DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH:/usr/local/lib
```

On Windows, ensure the liboqs DLL is in your PATH or in the same directory as your Python script.

#### Unsupported Algorithm Error

If you see `KeyError: The requested KEM algorithm is not supported`, verify that the algorithm is enabled in your liboqs build.

**Solution:**

Rebuild liboqs with your required algorithms enabled by modifying the CMake configuration.

### Verifying Installation

Run the following Python code to verify that liboqs is correctly installed:

```python
import oqs

# Print available KEM mechanisms
print("Enabled KEM mechanisms:")
for alg in oqs.get_enabled_KEM_mechanisms():
    print(f" - {alg}")

# Verify that Kyber768 is available
assert "Kyber768" in oqs.get_enabled_KEM_mechanisms(), "Kyber768 is not available"
print("Kyber768 is available!")
```

## Next Steps

After successful installation, you can:

1. Run the application: `streamlit run pqc_app.py`
2. Generate your first key pair
3. Start encrypting and decrypting files 