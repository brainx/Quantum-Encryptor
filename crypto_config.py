# crypto_config.py
import oqs

class CryptoConfig:
    """Configuration constants for the cryptographic operations."""

    # --- KEM Algorithm ---
    # Choose a NIST standard KEM. Ensure it's enabled in your liboqs build.
    # Available KEMs can be listed via: print(oqs.get_enabled_KEM_mechanisms())
    KEM_ALG = "Kyber768" # ML-KEM-768

    # --- Data Encryption (DEM) ---
    AES_KEY_BYTES = 32  # AES-256
    AES_NONCE_BYTES = 12 # Standard GCM nonce size (96 bits)
    AES_TAG_BYTES = 16  # Standard GCM tag size (128 bits)

    # --- Key Derivation (KDF) ---
    # For deriving AES key from KEM shared secret
    HKDF_SALT = b"pqc-file-enc-hkdf-salt" # Optional salt for HKDF
    HKDF_INFO_AES = b"pqc-file-enc-aes-key-derivation" # Context for AES key derivation

    # For deriving key from password for private key encryption
    PBKDF2_SALT_BYTES = 16 # Recommended salt size
    PBKDF2_ITERATIONS = 390000 # OWASP recommendation (adjust based on performance needs)
    # Use SHA256 for PBKDF2 HMAC
    PBKDF2_HASH_ALG = "sha256"
    # Context info for deriving private key encryption key
    HKDF_INFO_PRIVATE_KEY = b"pqc-private-key-encryption"

    # --- File Format ---
    MAGIC_BYTES = b"PQCENC"
    FORMAT_VERSION = 2 # Increment version due to potential private key encryption changes

    # Header structure (fixed part): Magic(6s), Version(H=ushort)
    HEADER_BASE_FORMAT = ">6s H"
    # Variable parts (lengths determined at runtime):
    # KEM Algo Len(H), KEM Algo(s), KEM CT Len(I=uint), KEM CT(s), Nonce(s)

    # --- PEM Key Format ---
    PEM_PUBLIC_HEADER = "-----BEGIN PQC PUBLIC KEY-----"
    PEM_PUBLIC_FOOTER = "-----END PQC PUBLIC KEY-----"
    PEM_PRIVATE_HEADER = "-----BEGIN PQC PRIVATE KEY-----"
    PEM_PRIVATE_FOOTER = "-----END PQC PRIVATE KEY-----"
    PEM_ALGORITHM_HEADER = "Algorithm: "
    # Headers for encrypted private keys
    PEM_PROC_TYPE_HEADER = "Proc-Type: 4,ENCRYPTED"
    PEM_DEK_INFO_HEADER = "DEK-Info: AES-256-GCM," # Followed by salt_b64,nonce_b64

    # --- General ---
    # FILE_BUFFER_SIZE = 1024 * 1024 # 1 MB (Relevant if streaming were implemented)

# Instantiate the config for easy import
cfg = CryptoConfig()

# Perform a quick check that the chosen KEM is available
try:
    if cfg.KEM_ALG not in oqs.get_enabled_KEM_mechanisms():
         raise RuntimeError(f"FATAL: Configured KEM algorithm '{cfg.KEM_ALG}' is not enabled in liboqs.")
except Exception as e:
     # This might fail if liboqs isn't installed/working correctly yet
     print(f"Warning: Could not verify KEM availability at config load time: {e}")