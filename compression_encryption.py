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

HEADER_LENGTH = 18
NONCE_SIZE = 12
TAG_SIZE = 16
AES_KEY_SIZE = 32

class QuantumKeyExchange:
    """
    Simplified QKE implementation for GOOSE/RSV communication
    In a real quantum system, this would use quantum channels
    """
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.key_sequence = 0
        self.quantum_channel_simulation = True  # Flag for simulation mode
        self.key_storage_path = f"quantum_keys_{node_id}"
        if not os.path.exists(self.key_storage_path):
            os.makedirs(self.key_storage_path)
        
    def _get_key_file_path(self, peer_id: str) -> str:
        """Generate file path for storing peer's key"""
        return os.path.join(self.key_storage_path, f"key_{peer_id}.bin")
    
    def _save_key_to_file(self, peer_id: str, key_data: dict):
        """Save key data to file"""
        file_path = self._get_key_file_path(peer_id)
        with open(file_path, 'wb') as f:
            # Save key, timestamp, and sequence as bytes
            f.write(key_data['key'])
            f.write(int(key_data['timestamp']).to_bytes(8, byteorder='big'))
            f.write(key_data['sequence'].to_bytes(4, byteorder='big'))
    
    def _load_key_from_file(self, peer_id: str) -> Optional[dict]:
        """Load key data from file"""
        file_path = self._get_key_file_path(peer_id)
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, 'rb') as f:
                key_data = f.read()
                if len(key_data) < AES_KEY_SIZE + 8 + 4:  # key + timestamp + sequence
                    return None
                key = key_data[:AES_KEY_SIZE]
                timestamp = int.from_bytes(key_data[AES_KEY_SIZE:AES_KEY_SIZE+8], byteorder='big')
                sequence = int.from_bytes(key_data[AES_KEY_SIZE+8:], byteorder='big')
                return {
                    'key': key,
                    'timestamp': timestamp,
                    'sequence': sequence
                }
        except Exception:
            return None
    
    def generate_quantum_bits(self, length: int) -> List[int]:
        """
        Simulate quantum bit generation
        In real QKE, this would use quantum photon polarization
        """
        return [secrets.randbelow(2) for _ in range(length)]
    
    def generate_random_bases(self, length: int) -> List[int]:
        """
        Generate random measurement bases (0 or 1)
        In real QKE: 0 = rectilinear, 1 = diagonal
        """
        return [secrets.randbelow(2) for _ in range(length)]
    
    def measure_qubits(self, qubits: List[int], bases: List[int]) -> List[int]:
        """
        Simulate qubit measurement with bases
        In real QKE, incompatible bases would give random results
        """
        measured = []
        for qubit, base in zip(qubits, bases):
            if secrets.randbelow(2) == 0:  # Simulate basis compatibility
                measured.append(qubit)
            else:
                measured.append(secrets.randbelow(2))  # Random bit
        return measured
    
    def sift_key(self, alice_bases: List[int], bob_bases: List[int], 
                 alice_bits: List[int]) -> Tuple[List[int], List[int]]:
        """
        Sift the key by keeping only bits where bases matched
        """
        sifted_bits = []
        matching_indices = []
        
        for i, (a_base, b_base) in enumerate(zip(alice_bases, bob_bases)):
            if a_base == b_base:
                sifted_bits.append(alice_bits[i])
                matching_indices.append(i)
        
        return sifted_bits, matching_indices
    
    def error_correction(self, key_bits: List[int], 
                        error_rate: float = 0.1) -> List[int]:
        """
        Simple error correction simulation
        In real QKE, would use advanced error correction codes
        """
        corrected = []
        for bit in key_bits:
            if secrets.randbelow(100) < error_rate * 100:
                corrected.append(1 - bit)  # Flip bit (error correction)
            else:
                corrected.append(bit)
        return corrected
    
    def privacy_amplification(self, key_bits: List[int], 
                            target_length: int = 256) -> bytes:
        """
        Convert quantum key bits to usable encryption key
        Uses HKDF for key derivation
        """
        key_bytes = bytearray()
        for i in range(0, len(key_bits), 8):
            byte_bits = key_bits[i:i+8]
            if len(byte_bits) == 8:
                byte_val = sum(bit << (7-j) for j, bit in enumerate(byte_bits))
                key_bytes.append(byte_val)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=target_length // 8,
            salt=None,
            info=b'QKE_GOOSE_RSV',
            backend=default_backend()
        )
        return hkdf.derive(bytes(key_bytes))
    
    def establish_quantum_key(self, peer_id: str, 
                            key_length: int = 2048) -> bytes:
        """
        Simulate the full QKE protocol (BB84-like)
        """
        print(f"Establishing quantum key with {peer_id}...")
        
        alice_bits = self.generate_quantum_bits(key_length)
        alice_bases = self.generate_random_bases(key_length)
        
        bob_bases = self.generate_random_bases(key_length)
        bob_bits = self.measure_qubits(alice_bits, bob_bases)
        
        sifted_bits, matching_indices = self.sift_key(
            alice_bases, bob_bases, alice_bits
        )
        
        print(f"Sifted key length: {len(sifted_bits)} bits")
        
        if len(sifted_bits) < 512:
            raise ValueError("Insufficient key material after sifting")
        
        corrected_bits = self.error_correction(sifted_bits)
        final_key = self.privacy_amplification(corrected_bits, 256)
        
        # Save key to file instead of memory
        key_data = {
            'key': final_key,
            'timestamp': time.time(),
            'sequence': self.key_sequence
        }
        self._save_key_to_file(peer_id, key_data)
        self.key_sequence += 1
        
        print(f"Quantum key established: {len(final_key)} bytes")
        return final_key
    
    def get_current_key(self, peer_id: str) -> Optional[bytes]:
        """Get the current quantum key for a peer from file"""
        key_data = self._load_key_from_file(peer_id)
        return key_data['key'] if key_data else None
    
    def refresh_key(self, peer_id: str) -> bytes:
        """Refresh the quantum key with a peer"""
        return self.establish_quantum_key(peer_id)

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
