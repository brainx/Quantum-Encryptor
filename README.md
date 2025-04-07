# Quantum Encryptor

A post-quantum cryptography tool for file encryption using quantum-resistant algorithms. This application combines post-quantum Key Encapsulation Mechanisms (KEM) with classical symmetric encryption to protect files against future quantum computer threats.

![Quantum Encryption](https://img.shields.io/badge/Encryption-Post--Quantum-blue)
![Python Version](https://img.shields.io/badge/Python-3.8%2B-green)

## Features

- **Post-Quantum Security**: Uses Kyber768 (ML-KEM-768), a NIST-approved post-quantum KEM algorithm
- **Hybrid Encryption**: Combines quantum-resistant key exchange with AES-256-GCM symmetric encryption
- **Password-Protected Keys**: Optional password encryption for private keys
- **User-Friendly Interface**: Simple web-based UI built with Streamlit
- **PEM Key Format**: Keys stored in standard PEM format with quantum algorithm extensions

## Requirements

- Python 3.8 or higher
- liboqs (Open Quantum Safe library)
- Dependencies listed in `requirements.txt`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/brainx/quantum-encryptor.git
   cd quantum-encryptor
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install liboqs (if not already installed):
   - On Ubuntu/Debian:
     ```bash
     sudo apt-get install cmake ninja-build
     git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
     cd liboqs
     mkdir build && cd build
     cmake -GNinja ..
     ninja
     sudo ninja install
     ```
   - On macOS:
     ```bash
     brew install cmake ninja
     git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
     cd liboqs
     mkdir build && cd build
     cmake -GNinja ..
     ninja
     sudo ninja install
     ```
   - On Windows:
     Follow the instructions at [Open Quantum Safe liboqs Windows build](https://github.com/open-quantum-safe/liboqs/wiki/Windows-Build).

## Usage

1. Start the application:
   ```bash
   streamlit run pqc_app.py
   ```

2. The web interface will open in your browser. You can:
   - Generate a new post-quantum key pair
   - Encrypt files using a recipient's public key
   - Decrypt files using your private key
   - Access key utilities

### Key Generation

1. Select "Generate Keys" from the sidebar
2. Choose whether to password-protect your private key
3. Generate the keys and download both public and private key files
4. Share your public key with others who want to send you encrypted files

### File Encryption

1. Select "Encrypt File" from the sidebar
2. Upload the file you want to encrypt
3. Upload the recipient's public key (.pem file)
4. Specify the output filename
5. Download the encrypted file

### File Decryption

1. Select "Decrypt File" from the sidebar
2. Upload the encrypted file (.pqc file)
3. Upload your private key (.pem file)
4. Enter your password if the private key is password-protected
5. Download the decrypted file

## Security Considerations

- This implementation provides post-quantum security based on the strength of the Kyber KEM algorithm
- The hybrid encryption approach ensures compatibility with today's security needs
- Password protection for private keys adds an additional layer of security
- **Disclaimer**: While developed with security best practices, this software should undergo security audit before use in production environments

## Project Structure

- `crypto_config.py` - Configuration parameters for cryptographic operations
- `crypto_core.py` - Core cryptographic functions (key generation, encryption, decryption)
- `pqc_app.py` - Streamlit web application interface

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

[Your Name]  
[Your Contact Information or Website]

## Acknowledgments

- [Open Quantum Safe](https://openquantumsafe.org/) for liboqs implementation
- [NIST](https://www.nist.gov/pqcrypto) for leading the post-quantum cryptography standardization effort 