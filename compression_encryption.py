import zlib
import os
import time
import hashlib
import secrets
from typing import Tuple, List, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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

class SecureGOOSEMessaging:
    """
    Enhanced GOOSE/RSV messaging with QKE
    """
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.qke = QuantumKeyExchange(node_id)
        self.key_refresh_interval = 3600  # 1 hour
        self.last_key_refresh = {}
        
    def ensure_quantum_key(self, peer_id: str) -> bytes:
        """
        Ensure we have a valid quantum key for the peer
        """
        current_time = time.time()
        
        if (peer_id not in self.last_key_refresh or 
            current_time - self.last_key_refresh[peer_id] > self.key_refresh_interval):
            
            key = self.qke.establish_quantum_key(peer_id)
            self.last_key_refresh[peer_id] = current_time
            return key
        
        return self.qke.get_current_key(peer_id)
    
    def compress_data(self, data: bytes) -> bytes:
        return zlib.compress(data)
    
    def decompress_data(self, data: bytes) -> bytes:
        return zlib.decompress(data)
    
    def encrypt_message(self, plaintext: bytes, peer_id: str) -> bytes:
        """
        Encrypt message using quantum-derived key
        """
        quantum_key = self.ensure_quantum_key(peer_id)
        nonce = os.urandom(NONCE_SIZE)
        cipher = Cipher(algorithms.AES(quantum_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce + ciphertext + encryptor.tag
    
    def decrypt_message(self, ciphertext_with_nonce_and_tag: bytes, 
                       peer_id: str) -> bytes:
        """
        Decrypt message using quantum-derived key
        """
        quantum_key = self.qke.get_current_key(peer_id)
        if not quantum_key:
            raise ValueError(f"No quantum key available for peer {peer_id}")
        
        nonce = ciphertext_with_nonce_and_tag[:NONCE_SIZE]
        ciphertext = ciphertext_with_nonce_and_tag[NONCE_SIZE:-TAG_SIZE]
        tag = ciphertext_with_nonce_and_tag[-TAG_SIZE:]
        
        cipher = Cipher(algorithms.AES(quantum_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
    def generate_quantum_hmac(self, message: bytes, peer_id: str) -> bytes:
        """
        Generate HMAC using quantum key
        """
        quantum_key = self.qke.get_current_key(peer_id)
        if not quantum_key:
            raise ValueError(f"No quantum key available for peer {peer_id}")
        
        h = HMAC(quantum_key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        return h.finalize()
    
    def process_goose_message(self, message_data: bytes, peer_id: str, 
                            encrypt: bool = True) -> bytes:
        """
        Process GOOSE message with optional encryption
        """
        compressed = self.compress_data(message_data)
        if encrypt:
            encrypted = self.encrypt_message(compressed, peer_id)
            hmac_tag = self.generate_quantum_hmac(encrypted, peer_id)
            return encrypted + hmac_tag
        else:
            return compressed
    
    def receive_goose_message(self, received_data: bytes, peer_id: str, 
                            encrypted: bool = True) -> bytes:
        """
        Receive and process GOOSE message
        """
        if encrypted:
            hmac_tag = received_data[-32:]
            encrypted_data = received_data[:-32]
            
            expected_hmac = self.generate_quantum_hmac(encrypted_data, peer_id)
            if hmac_tag != expected_hmac:
                raise ValueError("HMAC verification failed")
            
            decrypted = self.decrypt_message(encrypted_data, peer_id)
            return self.decompress_data(decrypted)
        else:
            return self.decompress_data(received_data)

# Example usage
if __name__ == "__main__":
    node_a = SecureGOOSEMessaging("SubstationA")
    node_b = SecureGOOSEMessaging("SubstationB")
    
    test_message = b"GOOSE message: Breaker status change - CB01 OPEN"
    
    print("=== Quantum Key Exchange Demo ===")
    
    encrypted_message = node_a.process_goose_message(test_message, "SubstationB")
    print(f"Encrypted message length: {len(encrypted_message)} bytes")
    
    # Copy key file for demo purposes
    import shutil
    key_file_a = node_a.qke._get_key_file_path("SubstationB")
    key_file_b = node_b.qke._get_key_file_path("SubstationA")
    if os.path.exists(key_file_a):
        shutil.copy(key_file_a, key_file_b)
    
    try:
        decrypted_message = node_b.receive_goose_message(encrypted_message, "SubstationA")
        print(f"Decrypted message: {decrypted_message.decode()}")
        print("✓ Quantum-secured communication successful!")
    except Exception as e:
        print(f"✗ Error: {e}")