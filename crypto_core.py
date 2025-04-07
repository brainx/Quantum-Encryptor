# crypto_core.py
import oqs
import os
import struct
import logging
import base64
import io
from typing import Optional, Tuple, Dict, Any

# Configuration
from crypto_config import cfg

# Cryptography Libraries
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag, InvalidKey # For password decryption
from cryptography.hazmat.backends import default_backend

# Setup Logger
logger = logging.getLogger(__name__)
# Configure root logger if not already configured by the app
if not logging.getLogger().hasHandlers():
     logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s')


# --- KEM Key Generation ---

def generate_oqs_keys(kem_alg: str = cfg.KEM_ALG) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Generates raw PQC public/private key pair bytes using OQS."""
    logger.info(f"Attempting to generate raw keys for KEM: {kem_alg}")
    public_key, secret_key = None, None # Ensure cleanup in finally block
    try:
        with oqs.KeyEncapsulation(kem_alg) as kem:
            if kem.details['length_public_key'] <= 0 or kem.details['length_secret_key'] <= 0:
                 logger.error(f"Invalid key length details for {kem_alg}. Cannot generate keys.")
                 return None, None

            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()

            # Basic validation
            if not public_key or not secret_key or \
               len(public_key) != kem.details['length_public_key'] or \
               len(secret_key) != kem.details['length_secret_key']:
                 logger.warning(f"Key generation for {kem_alg} produced unexpected key sizes or empty keys.")
                 # Decide if this should be a hard error or just a warning
                 # return None, None # Make it a hard error for safety

            logger.info(f"Successfully generated raw keys for {kem_alg}.")
            return public_key, secret_key
    except oqs.MechanismNotEnabledError:
        logger.error(f"KEM algorithm '{kem_alg}' is not enabled in this build of liboqs.")
        return None, None
    except Exception as e:
        logger.exception(f"Unexpected error generating OQS keys for {kem_alg}: {e}")
        return None, None
    finally:
         # Best effort to clear intermediate key copies if they exist
        if 'kem' in locals() and hasattr(kem, '__exit__'):
            pass # Context manager handles cleanup
        # Note: public_key, secret_key are returned or are None

# --- Key Derivation Functions ---

def derive_symmetric_key_hkdf(shared_secret: bytes) -> bytes:
    """Derives AES key from KEM shared secret using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=cfg.AES_KEY_BYTES,
        salt=cfg.HKDF_SALT,
        info=cfg.HKDF_INFO_AES,
        backend=default_backend()
    )
    derived_key = hkdf.derive(shared_secret)
    # Explicitly delete the input shared secret copy if possible
    del shared_secret
    return derived_key

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derives an encryption key from a password using PBKDF2-HMAC-SHA256."""
    if not password:
        raise ValueError("Password cannot be empty for key derivation.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=cfg.AES_KEY_BYTES, # Derive key suitable for AES-256
        salt=salt,
        iterations=cfg.PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    derived_key = kdf.derive(password.encode('utf-8'))
    # Explicitly delete password copy if possible (difficult in Python strings)
    password = "" # Overwrite local variable copy
    del password
    return derived_key


# --- Private Key Encryption/Decryption ---

def encrypt_private_key(raw_private_key: bytes, password: str) -> Tuple[Optional[bytes], Optional[bytes], Optional[bytes]]:
    """Encrypts raw private key bytes using AES-GCM with a key derived from password."""
    if not password:
         # If no password, return None for encrypted data (indicates not encrypted)
         return None, None, None

    salt = os.urandom(cfg.PBKDF2_SALT_BYTES)
    try:
        derived_key = derive_key_from_password(password, salt)
        nonce = os.urandom(cfg.AES_NONCE_BYTES)
        aesgcm = AESGCM(derived_key)
        encrypted_key = aesgcm.encrypt(nonce, raw_private_key, None) # No AAD needed here
        logger.info("Private key encrypted successfully.")
        return salt, nonce, encrypted_key
    except Exception as e:
        logger.exception(f"Failed to encrypt private key: {e}")
        return None, None, None
    finally:
        # Clean up derived key
        if 'derived_key' in locals(): del derived_key


def decrypt_private_key(encrypted_key_data: Dict[str, bytes], password: str) -> Optional[bytes]:
    """Decrypts private key bytes using AES-GCM with a key derived from password."""
    if not password:
        logger.error("Password required for decrypting the private key, but none provided.")
        return None

    salt = encrypted_key_data.get('salt')
    nonce = encrypted_key_data.get('nonce')
    encrypted_key = encrypted_key_data.get('encrypted_key')

    if not salt or not nonce or not encrypted_key:
         logger.error("Missing salt, nonce, or encrypted data for private key decryption.")
         return None

    derived_key = None # Ensure cleanup
    try:
        derived_key = derive_key_from_password(password, salt)
        aesgcm = AESGCM(derived_key)
        raw_private_key = aesgcm.decrypt(nonce, encrypted_key, None)
        logger.info("Private key decrypted successfully.")
        return raw_private_key
    except (InvalidTag, InvalidKey):
        logger.warning("Private key decryption failed: Invalid password or corrupted data (tag mismatch).")
        return None # Indicate wrong password or corruption
    except Exception as e:
        logger.exception(f"Failed to decrypt private key: {e}")
        return None
    finally:
         if derived_key: del derived_key


# --- PEM Key Handling ---

def save_key_pem(
    key_bytes: bytes,
    kem_alg: str,
    key_type: str,
    password: Optional[str] = None
) -> Optional[str]:
    """
    Saves key data (raw bytes) in PEM format. Encrypts private key if password is provided.

    Returns:
        PEM formatted string, or None on error.
    """
    if key_type not in ["public", "private"]:
        logger.error(f"Invalid key_type specified for saving: {key_type}")
        return None

    pem_data_lines = []
    is_encrypted = False
    dek_info = ""
    encoded_key_b64 = ""

    if key_type == "public":
        if password:
            logger.warning("Password provided for saving a public key, but public keys are not encrypted. Ignoring password.")
        pem_data_lines.append(cfg.PEM_PUBLIC_HEADER)
        pem_data_lines.append(f"{cfg.PEM_ALGORITHM_HEADER}{kem_alg}")
        encoded_key_b64 = base64.b64encode(key_bytes).decode('ascii')

    elif key_type == "private":
        pem_data_lines.append(cfg.PEM_PRIVATE_HEADER)
        if password:
            salt, nonce, encrypted_key = encrypt_private_key(key_bytes, password)
            if salt and nonce and encrypted_key:
                is_encrypted = True
                salt_b64 = base64.b64encode(salt).decode('ascii')
                nonce_b64 = base64.b64encode(nonce).decode('ascii')
                encoded_key_b64 = base64.b64encode(encrypted_key).decode('ascii')
                dek_info = f"{cfg.PEM_DEK_INFO_HEADER}{salt_b64},{nonce_b64}"
                pem_data_lines.append(cfg.PEM_PROC_TYPE_HEADER)
                pem_data_lines.append(dek_info)
                pem_data_lines.append(f"{cfg.PEM_ALGORITHM_HEADER}{kem_alg}") # Store algo even if encrypted
                logger.info("Saving encrypted private key to PEM.")
            else:
                logger.error("Failed to encrypt private key for PEM saving.")
                return None # Encryption failed
        else:
            # Save unencrypted private key
            pem_data_lines.append(f"{cfg.PEM_ALGORITHM_HEADER}{kem_alg}")
            encoded_key_b64 = base64.b64encode(key_bytes).decode('ascii')
            logger.info("Saving unencrypted private key to PEM.")

    # Add base64 key data, formatted to 64 chars per line
    pem_data_lines.extend([encoded_key_b64[i:i+64] for i in range(0, len(encoded_key_b64), 64)])

    # Add footer
    pem_data_lines.append(cfg.PEM_PUBLIC_FOOTER if key_type == "public" else cfg.PEM_PRIVATE_FOOTER)

    # Clean up intermediate sensitive data if private
    if key_type == "private":
        del key_bytes # Delete the raw key bytes copy
        if 'encrypted_key' in locals(): del encrypted_key

    return "\n".join(pem_data_lines) + "\n"


def load_key_pem(
    pem_content: str,
    password: Optional[str] = None
) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    """
    Loads key data from PEM string. Decrypts private key if necessary and password is provided.

    Returns:
        Tuple (raw_key_bytes, kem_algorithm, key_type), or (None, None, None) on error.
        key_type is 'public' or 'private'.
    """
    pem_content = pem_content.strip()
    lines = pem_content.splitlines()
    if not lines:
        logger.error("PEM content is empty.")
        return None, None, None

    header = lines[0]
    footer = lines[-1]
    key_type = None
    is_encrypted = False
    kem_alg = None
    dek_parts = {}
    key_b64_lines = []

    # Determine key type and check basic structure
    if header == cfg.PEM_PUBLIC_HEADER and footer == cfg.PEM_PUBLIC_FOOTER:
        key_type = "public"
        if password:
            logger.warning("Password provided when loading a public key. Ignoring password.")
    elif header == cfg.PEM_PRIVATE_HEADER and footer == cfg.PEM_PRIVATE_FOOTER:
        key_type = "private"
    else:
        logger.error("Invalid PEM format: Missing or mismatched headers/footers.")
        return None, None, None

    # Parse lines between header and footer
    for line in lines[1:-1]:
        line = line.strip()
        if not line: continue # Skip empty lines

        if line.startswith(cfg.PEM_ALGORITHM_HEADER):
            kem_alg = line[len(cfg.PEM_ALGORITHM_HEADER):].strip()
        elif line == cfg.PEM_PROC_TYPE_HEADER:
             if key_type == "private":
                 is_encrypted = True
             else:
                 logger.warning("Found encryption header in a public key PEM. Ignoring.")
        elif line.startswith(cfg.PEM_DEK_INFO_HEADER):
            if key_type == "private" and is_encrypted:
                 try:
                     dek_info_content = line[len(cfg.PEM_DEK_INFO_HEADER):]
                     salt_b64, nonce_b64 = dek_info_content.split(',', 1)
                     dek_parts['salt'] = base64.b64decode(salt_b64)
                     dek_parts['nonce'] = base64.b64decode(nonce_b64)
                 except (ValueError, base64.binascii.Error) as e:
                     logger.error(f"Invalid DEK-Info line format or base64 encoding: {e}")
                     return None, None, None
            else:
                 logger.warning("Found DEK-Info header unexpectedly. Ignoring.")
        else:
            # Assume it's base64 key data
            key_b64_lines.append(line)

    if not kem_alg:
        logger.error("Algorithm not specified in PEM file.")
        return None, None, None
    if not key_b64_lines:
        logger.error("No key data found in PEM file.")
        return None, None, None

    # Decode base64 data
    key_b64 = "".join(key_b64_lines)
    try:
        raw_or_encrypted_bytes = base64.b64decode(key_b64)
    except base64.binascii.Error as e:
        logger.error(f"Base64 decoding failed for key data: {e}")
        return None, None, None

    # Handle decryption if necessary
    if key_type == "private" and is_encrypted:
        if not password:
            logger.error("Private key is encrypted, but no password provided.")
            return None, None, None # Indicate password needed
        if 'salt' not in dek_parts or 'nonce' not in dek_parts:
             logger.error("Encrypted private key PEM is missing DEK-Info details (salt/nonce).")
             return None, None, None

        dek_parts['encrypted_key'] = raw_or_encrypted_bytes
        raw_key_bytes = decrypt_private_key(dek_parts, password)

        if raw_key_bytes is None:
            logger.error("Private key decryption failed (likely wrong password or corruption).")
            # Return None to signal failure, keep kem_alg and key_type known if needed?
            # Let's return all None for consistency on failure.
            return None, None, None
        else:
             logger.info(f"Successfully loaded and decrypted private key for algorithm {kem_alg}.")
             # Clean up intermediate encrypted bytes copy
             del raw_or_encrypted_bytes
             del dek_parts
             return raw_key_bytes, kem_alg, key_type

    elif key_type == "private": # Unencrypted private key
         logger.info(f"Successfully loaded unencrypted private key for algorithm {kem_alg}.")
         return raw_or_encrypted_bytes, kem_alg, key_type
    else: # Public key
        logger.info(f"Successfully loaded public key for algorithm {kem_alg}.")
        return raw_or_encrypted_bytes, kem_alg, key_type


def get_key_info_pem(pem_content: str) -> Tuple[Optional[str], Optional[str], bool]:
    """
    Quickly inspects PEM content to get Algorithm, Key Type, and Encryption Status.
    Does not validate the key bytes themselves.

    Returns:
        Tuple (kem_algorithm, key_type, is_encrypted), or (None, None, False) on error.
    """
    pem_content = pem_content.strip()
    lines = pem_content.splitlines()
    if not lines: return None, None, False

    header = lines[0]
    footer = lines[-1]
    key_type = None
    is_encrypted = False
    kem_alg = None

    if header == cfg.PEM_PUBLIC_HEADER and footer == cfg.PEM_PUBLIC_FOOTER:
        key_type = "Public"
    elif header == cfg.PEM_PRIVATE_HEADER and footer == cfg.PEM_PRIVATE_FOOTER:
        key_type = "Private"
    else:
        return None, None, False # Invalid format

    for line in lines[1:-1]:
        line = line.strip()
        if line.startswith(cfg.PEM_ALGORITHM_HEADER):
            kem_alg = line[len(cfg.PEM_ALGORITHM_HEADER):].strip()
        elif line == cfg.PEM_PROC_TYPE_HEADER and key_type == "Private":
            is_encrypted = True
        # No need to parse DEK-Info or key data for this function

    if not kem_alg:
        return None, key_type, is_encrypted # Algo missing

    return kem_alg, key_type, is_encrypted


# --- File Encryption / Decryption ---

def encrypt_file_pro(
    input_data: bytes,
    public_key_bytes: bytes,
    kem_alg: str = cfg.KEM_ALG
) -> Optional[bytes]:
    """Encrypts input data using PQC KEM + AES-GCM with defined file format."""
    logger.info(f"Starting encryption with KEM: {kem_alg}")
    if not input_data:
        logger.warning("Input data for encryption is empty.")
        # Decide if empty files should be encrypted or raise error
        # Let's allow encrypting empty files for now.

    shared_secret_sender = None
    aes_key = None
    output_buffer = io.BytesIO()

    try:
        with oqs.KeyEncapsulation(kem_alg) as kem:
            # 1. KEM Encapsulation
            ciphertext_kem, shared_secret_sender = kem.encap_secret(public_key_bytes)

            # 2. Derive AES Key securely
            aes_key = derive_symmetric_key_hkdf(shared_secret_sender)
            shared_secret_sender = b'' # Zero out intermediate secret

            # 3. Generate Nonce
            nonce = os.urandom(cfg.AES_NONCE_BYTES)

            # 4. AES-GCM Encryption
            aesgcm = AESGCM(aes_key)
            encrypted_data_aes = aesgcm.encrypt(nonce, input_data, None) # No AAD

            # 5. Construct File Header
            kem_alg_bytes = kem_alg.encode('utf-8')
            # Pack fixed part
            output_buffer.write(struct.pack(cfg.HEADER_BASE_FORMAT, cfg.MAGIC_BYTES, cfg.FORMAT_VERSION))
            # Pack variable parts: Algo Len, Algo, CT Len, CT, Nonce
            # Use explicit packing formats for clarity
            output_buffer.write(struct.pack('>H', len(kem_alg_bytes))) # Algo name len (ushort)
            output_buffer.write(kem_alg_bytes)
            output_buffer.write(struct.pack('>I', len(ciphertext_kem))) # KEM CT len (uint)
            output_buffer.write(ciphertext_kem)
            output_buffer.write(nonce) # Nonce (fixed size defined in cfg)

            # 6. Append Encrypted Data
            output_buffer.write(encrypted_data_aes)

            encrypted_blob = output_buffer.getvalue()
            logger.info(f"Encryption successful. Output size: {len(encrypted_blob)} bytes.")
            return encrypted_blob

    except oqs.MechanismNotEnabledError:
        logger.error(f"KEM algorithm '{kem_alg}' is not enabled during encryption.")
        return None
    except Exception as e:
        logger.exception(f"Unexpected error during encryption: {e}")
        return None
    finally:
        # Best effort cleanup
        if aes_key: aes_key = b'' # Zero out AES key
        del aes_key
        if shared_secret_sender: shared_secret_sender = b''
        del shared_secret_sender
        if 'kem' in locals() and hasattr(kem, '__exit__'): pass
        if 'ciphertext_kem' in locals(): del ciphertext_kem
        if 'nonce' in locals(): del nonce
        if 'encrypted_data_aes' in locals(): del encrypted_data_aes
        output_buffer.close()


def decrypt_file_pro(
    encrypted_blob: bytes,
    secret_key_bytes: bytes,
) -> Optional[bytes]:
    """Decrypts data using PQC KEM + AES-GCM and defined file format."""
    logger.info("Starting decryption process.")
    if not encrypted_blob:
        logger.error("Input data for decryption is empty.")
        return None

    input_buffer = io.BytesIO(encrypted_blob)
    shared_secret_receiver = None
    aes_key = None
    kem_alg_from_file = None

    try:
        # 1. Read and Validate Fixed Header
        header_fixed_size = struct.calcsize(cfg.HEADER_BASE_FORMAT)
        header_fixed_part = input_buffer.read(header_fixed_size)
        if len(header_fixed_part) < header_fixed_size:
            raise ValueError("File too short - truncated fixed header.")

        magic, version = struct.unpack(cfg.HEADER_BASE_FORMAT, header_fixed_part)

        if magic != cfg.MAGIC_BYTES:
            logger.error(f"Invalid magic bytes. Expected {cfg.MAGIC_BYTES!r}, got {magic!r}.")
            return None # Not our file format
        if version > cfg.FORMAT_VERSION:
            logger.warning(f"File format version ({version}) is newer than supported ({cfg.FORMAT_VERSION}). Decryption may fail.")
            # Allow attempt, but could be made stricter
        elif version < cfg.FORMAT_VERSION:
             logger.info(f"File format version ({version}) is older than current ({cfg.FORMAT_VERSION}). Attempting decryption.")

        logger.info(f"Header validated: Magic={magic!r}, Version={version}")

        # 2. Read Variable Header Part
        # Algo Len (H)
        kem_alg_len_bytes = input_buffer.read(struct.calcsize('>H'))
        if len(kem_alg_len_bytes) < struct.calcsize('>H'): raise ValueError("Truncated header (KEM algo len).")
        kem_alg_len = struct.unpack('>H', kem_alg_len_bytes)[0]
        if kem_alg_len > 500: raise ValueError("Implausible KEM Algo length in header.") # Sanity check

        # Algo Name (kem_alg_len bytes)
        kem_alg_bytes = input_buffer.read(kem_alg_len)
        if len(kem_alg_bytes) < kem_alg_len: raise ValueError("Truncated header (KEM algo name).")
        kem_alg_from_file = kem_alg_bytes.decode('utf-8')
        logger.info(f"KEM algorithm from file: {kem_alg_from_file}")

        # KEM CT Len (I)
        kem_ct_len_bytes = input_buffer.read(struct.calcsize('>I'))
        if len(kem_ct_len_bytes) < struct.calcsize('>I'): raise ValueError("Truncated header (KEM CT len).")
        kem_ct_len = struct.unpack('>I', kem_ct_len_bytes)[0]
        # Add sanity check for CT length based on KEM? Might be complex.
        # if kem_ct_len > reasonable_max: raise ValueError("Implausible KEM CT length.")

        # KEM CT (kem_ct_len bytes)
        ciphertext_kem = input_buffer.read(kem_ct_len)
        if len(ciphertext_kem) < kem_ct_len: raise ValueError("Truncated header (KEM CT).")

        # Nonce (fixed size)
        nonce = input_buffer.read(cfg.AES_NONCE_BYTES)
        if len(nonce) < cfg.AES_NONCE_BYTES: raise ValueError("Truncated header (Nonce).")

        # Rest is AES encrypted data
        encrypted_data_aes = input_buffer.read()
        if not encrypted_data_aes:
             # Only valid if original file was empty AND AES GCM allows empty encryption
             # (which it generally does, resulting mostly in just the tag)
             logger.warning("AES encrypted data part is empty. Original file might have been empty.")
             # Proceed cautiously

        logger.debug("File header parsed successfully.")

        # 3. KEM Decapsulation
        logger.debug(f"Performing KEM decapsulation with {kem_alg_from_file}...")
        with oqs.KeyEncapsulation(kem_alg_from_file) as kem:
            # Verify secret key length matches the algorithm expectation?
            if len(secret_key_bytes) != kem.details['length_secret_key']:
                 logger.warning(f"Provided secret key length ({len(secret_key_bytes)}) doesn't match expected length ({kem.details['length_secret_key']}) for KEM {kem_alg_from_file}. Decapsulation might fail.")
                 # Proceed but be wary, could indicate wrong key type used.

            shared_secret_receiver = kem.decap_secret(secret_key_bytes, ciphertext_kem)
            logger.debug("KEM decapsulation successful.")

        # 4. Derive AES Key securely
        aes_key = derive_symmetric_key_hkdf(shared_secret_receiver)
        shared_secret_receiver = b'' # Zero out intermediate secret

        # 5. AES-GCM Decryption
        logger.debug("Performing AES-GCM decryption...")
        aesgcm = AESGCM(aes_key)
        try:
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data_aes, None) # No AAD
            logger.info("AES-GCM decryption and authentication successful.")
            return decrypted_data
        except InvalidTag:
            logger.error("AES-GCM decryption failed: Authentication tag mismatch.")
            # This is a critical failure - indicates corruption, tampering, or wrong key
            return None # Return None explicitly on auth failure
        except Exception as e_aes:
            logger.exception(f"AES-GCM decryption failed unexpectedly: {e_aes}")
            return None # Other AES errors

    except oqs.MechanismNotEnabledError:
        logger.error(f"KEM algorithm '{kem_alg_from_file}' from file is not enabled.")
        return None
    except struct.error as e_struct:
        logger.error(f"File format error during header unpacking: {e_struct}")
        return None # Indicates corruption
    except ValueError as e_val: # Catch our explicit header validation errors
        logger.error(f"Invalid or truncated file header: {e_val}")
        return None
    except UnicodeDecodeError:
        logger.error("Failed to decode KEM algorithm name from file header (corrupted?).")
        return None
    except Exception as e:
        logger.exception(f"Unexpected error during decryption: {e}")
        return None
    finally:
        # Best effort cleanup
        if aes_key: aes_key = b''
        del aes_key
        if shared_secret_receiver: shared_secret_receiver = b''
        del shared_secret_receiver
        if 'kem' in locals() and hasattr(kem, '__exit__'): pass
        if 'ciphertext_kem' in locals(): del ciphertext_kem
        if 'nonce' in locals(): del nonce
        if 'encrypted_data_aes' in locals(): del encrypted_data_aes
        input_buffer.close()