"""
Diffie-Hellman Key Exchange Implementation
"""
import random


class DiffieHellman:
    """Diffie-Hellman Key Exchange"""

    def __init__(self):
        self.p = 23  # Small prime for demo
        self.g = 5  # Generator
        self.private_key = None
        self.public_key = None
        self.shared_secret = None

    def generate_private_key(self):
        """Generate private key"""
        self.private_key = random.randint(2, self.p - 2)
        return self.private_key

    def compute_public_key(self):
        """Compute public key: g^x mod p"""
        if not self.private_key:
            self.generate_private_key()
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key

    def compute_shared_secret(self, other_public_key):
        """Compute shared secret: public_key^private_key mod p"""
        self.shared_secret = pow(other_public_key, self.private_key, self.p)
        return self.shared_secret

    def get_params(self):
        """Get DH parameters"""
        return {"p": self.p, "g": self.g}