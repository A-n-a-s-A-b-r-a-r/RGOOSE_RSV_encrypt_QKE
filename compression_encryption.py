import zlib, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from QKE import BB84Simulator

HEADER_LENGTH = 18  # Length of the PDU header (example)
NONCE_SIZE = 12  # Nonce size for AES-GCM in bytes
TAG_SIZE = 16  # Tag size for AES-GCM in bytes
AES_KEY_SIZE = 32  # AES-256 key size in bytes
KEY_FILE_PATH = "encryption_key.bin"  # Path to store the key file

def compress_data(data: bytes) -> bytes:
    return zlib.compress(data)

def decompress_data(data: bytes) -> bytes:
    return zlib.decompress(data)

def save_key_to_file(key: bytes, filepath: str = KEY_FILE_PATH):
    """Save the encryption key to a file"""
    with open(filepath, 'wb') as f:
        f.write(key)

def load_key_from_file(filepath: str = KEY_FILE_PATH) -> bytes:
    """Load the encryption key from a file"""
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        # If key file doesn't exist, use the default key and save it
        default_key = b'\xe3\x1e\xc3G\x8f\x98|\x15u\xf3`\xf2\xdc7\xe1 \x00\xdc\x1a\x85\t6B\x13\x8d\xcd\xfcu\xcd\x08{A'
        save_key_to_file(default_key, filepath)
        return default_key

def encrypt_aes_gcm(plaintext: bytes) -> bytes:
    key = load_key_from_file()
    nonce = os.urandom(NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce + ciphertext + encryptor.tag

def decrypt_aes_gcm(ciphertext_with_nonce_and_tag: bytes) -> bytes:
    key = load_key_from_file()
    nonce = ciphertext_with_nonce_and_tag[:NONCE_SIZE]
    ciphertext = ciphertext_with_nonce_and_tag[NONCE_SIZE:-TAG_SIZE]
    tag = ciphertext_with_nonce_and_tag[-TAG_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def generate_hmac_cryptography(message):
    """Generate HMAC using the key from file"""
    key = load_key_from_file()
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(bytes(message))  # Convert list of integers to bytes
    return h.finalize()  # Return raw bytes (not hex)

def initialise_key():
    """Initialize key using BB84 simulator and save to file"""
    simulator1 = BB84Simulator()
    alice_key1, bob_key1, error_rate1 = simulator1.run_bb84(256, with_eavesdropper=False)  # Generate 256 bits
    
    # Convert bits to bytes properly
    key_bits = alice_key1[:256]  # Ensure exactly 256 bits
    key = int(''.join(map(str, key_bits)), 2).to_bytes(32, 'big')
    
    # Save the key to file
    save_key_to_file(key)
    print(f"Initialised key: {key}")
    print(f"Key saved to: {KEY_FILE_PATH}")

def delete_key_file(filepath: str = KEY_FILE_PATH):
    """Delete the key file (useful for cleanup or key rotation)"""
    try:
        os.remove(filepath)
        print(f"Key file {filepath} deleted successfully")
    except FileNotFoundError:
        print(f"Key file {filepath} not found")