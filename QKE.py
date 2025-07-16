import random
import numpy as np

class BB84Simulator:
    def __init__(self):
        self.alice_bits = []
        self.alice_bases = []
        self.bob_bases = []
        self.bob_measurements = []
        self.shared_key = []
        
    def generate_random_bits(self, length):
        """Generate random bits for Alice"""
        return [random.randint(0, 1) for _ in range(length)]
    
    def generate_random_bases(self, length):
        """Generate random bases (0 for rectilinear, 1 for diagonal)"""
        return [random.randint(0, 1) for _ in range(length)]
    
    def encode_photon(self, bit, basis):
        """
        Encode a bit using a specific basis
        Basis 0 (rectilinear): 0 = horizontal, 1 = vertical
        Basis 1 (diagonal): 0 = 45°, 1 = 135°
        """
        if basis == 0:  # Rectilinear
            return 'H' if bit == 0 else 'V'
        else:  # Diagonal
            return 'D' if bit == 0 else 'A'
    
    def measure_photon(self, polarization, basis):
        """
        Measure a photon with a specific basis
        Returns the measured bit
        """
        if basis == 0:  # Measuring with rectilinear basis
            if polarization in ['H', 'V']:
                return 0 if polarization == 'H' else 1
            else:  # Diagonal photon measured with rectilinear basis
                return random.randint(0, 1)  # Random result
        else:  # Measuring with diagonal basis
            if polarization in ['D', 'A']:
                return 0 if polarization == 'D' else 1
            else:  # Rectilinear photon measured with diagonal basis
                return random.randint(0, 1)  # Random result
    
    def simulate_eavesdropper(self, photons, eavesdrop_probability=0.5):
        """
        Simulate an eavesdropper (Eve) who intercepts some photons
        """
        intercepted_photons = []
        for photon in photons:
            if random.random() < eavesdrop_probability:
                # Eve measures with random basis
                eve_basis = random.randint(0, 1)
                eve_bit = self.measure_photon(photon, eve_basis)
                # Eve resends photon based on her measurement
                new_photon = self.encode_photon(eve_bit, eve_basis)
                intercepted_photons.append(new_photon)
            else:
                intercepted_photons.append(photon)
        return intercepted_photons
    
    def run_bb84(self, key_length=100, with_eavesdropper=False):
        """
        Run the complete BB84 protocol
        """
        print(f"Starting BB84 simulation with {key_length} bits")
        print("=" * 50)
        
        # Step 1: Alice prepares random bits and bases
        self.alice_bits = self.generate_random_bits(key_length)
        self.alice_bases = self.generate_random_bases(key_length)
        
        # Step 2: Alice encodes photons
        photons = []
        for i in range(key_length):
            photon = self.encode_photon(self.alice_bits[i], self.alice_bases[i])
            photons.append(photon)
        
        print(f"Alice's bits:  {self.alice_bits[:20]}...")
        print(f"Alice's bases: {self.alice_bases[:20]}...")
        print(f"Photons sent:  {photons[:20]}...")
        
        # Optional: Simulate eavesdropper
        if with_eavesdropper:
            print("\n🕵️ Eavesdropper (Eve) is intercepting!")
            photons = self.simulate_eavesdropper(photons)
        
        # Step 3: Bob chooses random bases and measures
        self.bob_bases = self.generate_random_bases(key_length)
        self.bob_measurements = []
        
        for i in range(key_length):
            measurement = self.measure_photon(photons[i], self.bob_bases[i])
            self.bob_measurements.append(measurement)
        
        print(f"\nBob's bases:        {self.bob_bases[:20]}...")
        print(f"Bob's measurements: {self.bob_measurements[:20]}...")
        
        # Step 4: Basis reconciliation (public discussion)
        matching_indices = []
        for i in range(key_length):
            if self.alice_bases[i] == self.bob_bases[i]:
                matching_indices.append(i)
        
        print(f"\nMatching bases at positions: {matching_indices[:10]}...")
        print(f"Total matching bases: {len(matching_indices)}")
        
        # Step 5: Extract shared key from matching bases
        alice_key = [self.alice_bits[i] for i in matching_indices]
        bob_key = [self.bob_measurements[i] for i in matching_indices]
        
        # Step 6: Error checking
        errors = sum(1 for a, b in zip(alice_key, bob_key) if a != b)
        error_rate = errors / len(alice_key) if alice_key else 0
        
        print(f"\nShared key length: {len(alice_key)}")
        print(f"Alice's key: {alice_key[:20]}...")
        print(f"Bob's key:   {bob_key[:20]}...")
        print(f"Errors: {errors}")
        print(f"Error rate: {error_rate:.2%}")
        
        # Determine if communication is secure
        expected_error_rate = 0.25 if with_eavesdropper else 0.0
        if error_rate > expected_error_rate + 0.05:  # 5% tolerance
            print("\n❌ HIGH ERROR RATE DETECTED! Possible eavesdropping!")
            print("Protocol should be aborted.")
        else:
            print("\n✅ Error rate is acceptable. Key exchange successful!")
            self.shared_key = alice_key  # In practice, further processing would be done
        
        return alice_key, bob_key, error_rate

# Example usage
if __name__ == "__main__":
    # Simulation without eavesdropper
    print("SIMULATION 1: Normal BB84 (no eavesdropper)")
    simulator1 = BB84Simulator()
    alice_key1, bob_key1, error_rate1 = simulator1.run_bb84(50, with_eavesdropper=False)
    
    print("\n" + "="*80 + "\n")
    
    # Simulation with eavesdropper
    print("SIMULATION 2: BB84 with eavesdropper")
    simulator2 = BB84Simulator()
    alice_key2, bob_key2, error_rate2 = simulator2.run_bb84(50, with_eavesdropper=True)
    
    print(f"\nSUMMARY:")
    print(f"Normal protocol error rate: {error_rate1:.2%}")
    print(f"With eavesdropper error rate: {error_rate2:.2%}")