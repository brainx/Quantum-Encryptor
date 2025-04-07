# Security Considerations

This document outlines the security considerations for the Quantum Encryptor application, including the cryptographic primitives used, potential threats, and best practices.

## Cryptographic Design

The application uses a hybrid cryptographic approach, combining post-quantum key encapsulation with classical symmetric encryption:

1. **Key Encapsulation Mechanism (KEM)**: Kyber768 (ML-KEM-768)
   - NIST-selected post-quantum cryptographic algorithm
   - Designed to resist attacks from both classical and quantum computers
   - Provides ~140 bits of security against quantum attacks

2. **Data Encryption Mechanism (DEM)**: AES-256-GCM
   - Authenticated encryption with associated data (AEAD)
   - Provides confidentiality, integrity, and authenticity
   - 256-bit key length provides sufficient security margin

3. **Key Derivation Function (KDF)**: HKDF-SHA256
   - Derives symmetric encryption keys from KEM shared secrets
   - Uses domain separation to prevent key reuse across different contexts

4. **Password-based Key Derivation**: PBKDF2-HMAC-SHA256
   - Used for deriving keys from passwords for private key protection
   - Configurable iteration count (default: 390,000 iterations)
   - Salt size: 16 bytes (128 bits)

## Threat Model

The application is designed to protect against the following threats:

1. **Quantum Computing Attacks**
   - Shor's algorithm breaking RSA/ECC-based encryption
   - Grover's algorithm reducing symmetric encryption strength

2. **Classical Cryptographic Attacks**
   - Brute force attacks on encryption keys
   - Side-channel attacks on implementation

3. **Password-related Threats**
   - Weak passwords used for private key protection
   - Brute force attacks on password-protected keys

4. **Implementation Vulnerabilities**
   - Memory leaks exposing sensitive information
   - Improper key management

## Security Best Practices

To maximize the security of the application, follow these best practices:

### Key Management

1. **Private Key Protection**
   - Always use strong, unique passwords for private key encryption
   - Store private keys securely, ideally offline or in hardware security modules
   - Limit access to private key files using OS-level permissions

2. **Key Rotation**
   - Periodically generate new key pairs
   - Re-encrypt sensitive files with new keys

3. **Backup Management**
   - Securely back up private keys
   - Consider key recovery mechanisms for organizational use

### Usage Recommendations

1. **File Encryption**
   - Encrypt files before transferring them over untrusted networks
   - Verify the authenticity of public keys before use

2. **Password Selection**
   - Use high-entropy passwords (at least 16 characters)
   - Consider using password managers to generate and store strong passwords

3. **Secure Environment**
   - Run the application on trusted, up-to-date systems
   - Be aware of physical security (shoulder surfing, etc.)

## Limitations

The application has the following security limitations:

1. **Cryptographic Algorithm Status**
   - Kyber is relatively new, and cryptanalysis is ongoing
   - Future discoveries might reveal weaknesses

2. **Implementation Considerations**
   - The application relies on the security of underlying libraries (liboqs, cryptography)
   - No formal verification or independent security audit has been performed

3. **Side-Channel Resistance**
   - The implementation does not provide explicit protections against timing attacks or other side channels
   - Hardware-level attacks (cache timing, power analysis) are not mitigated

## Reporting Security Issues

If you discover a security vulnerability in the application, please report it responsibly. Contact [security email] with details of the vulnerability, and allow time for the issue to be addressed before public disclosure.

## References

1. NIST Post-Quantum Cryptography Standardization: https://csrc.nist.gov/Projects/post-quantum-cryptography
2. Kyber Algorithm Specification: https://pq-crystals.org/kyber/
3. OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html 