# Test Suite for Quantum Encryptor

This directory contains unit tests for the Quantum Encryptor application.

## Running Tests

To run the tests, execute the following from the project root:

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=. tests/

# Run a specific test file
pytest tests/test_crypto_core.py

# Run a specific test class
pytest tests/test_crypto_core.py::TestKeyGeneration

# Run a specific test
pytest tests/test_crypto_core.py::TestKeyGeneration::test_generate_oqs_keys
```

## Test Structure

The tests are organized by module and functionality:

- `test_crypto_core.py` - Tests for the core cryptographic functions
  - Key generation and management
  - Key derivation
  - Private key encryption/decryption
  - PEM format handling
  - File encryption/decryption

## Writing New Tests

When adding features or fixing bugs, please add corresponding tests:

1. Create test functions with descriptive names
2. Follow the naming convention `test_<function_name>_<scenario>`
3. Add appropriate assertions
4. Use fixtures for common setup and teardown
5. Follow the existing class structure

## Dependencies

Test dependencies:
- pytest
- pytest-cov

Install these with:
```bash
pip install pytest pytest-cov
```

## Continuous Integration

The tests are automatically run as part of the CI/CD pipeline when changes are pushed to the repository.

## Coverage Goals

- Aim for at least 80% test coverage on core modules
- Prioritize coverage of security-critical functionality 