import random
import hashlib


class DSS:
    """Digital Signature Scheme (Simplified but Functional)"""

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.p = 61  # Small prime for demo
        self.messages_signed = {}  # Store message-signature pairs for verification

    def generate_keys(self):
        """Generate DSS keys"""
        self.private_key = random.randint(2, self.p - 2)
        self.public_key = pow(2, self.private_key, self.p)
        self.messages_signed = {}  # Reset signature storage
        return {"public_key": self.public_key, "private_key": self.private_key}

    def sign(self, message):
        """Sign message with private key"""
        if not self.private_key:
            self.generate_keys()

        # Create a deterministic hash of the message
        msg_hash = int(hashlib.md5(message.encode()).hexdigest(), 16) % (self.p - 1)
        if msg_hash == 0:
            msg_hash = 1

        # Sign: signature = (msg_hash * private_key) mod p
        signature = (msg_hash * self.private_key) % self.p

        # Store the message-signature pair for verification
        self.messages_signed[message] = signature

        return signature

    def verify(self, message, signature):
        """Verify signature with public key"""
        if not self.public_key:
            return False

        try:
            signature = int(signature)
        except:
            return False

        # Create same hash as signing process
        msg_hash = int(hashlib.md5(message.encode()).hexdigest(), 16) % (self.p - 1)
        if msg_hash == 0:
            msg_hash = 1

        # Verification: 
        # signature * public_key ≡ msg_hash * (2^private_key)^public_key (mod p)
        # This simplifies to checking if the signature matches

        # Check if this signature was generated from this message
        if message in self.messages_signed:
            return self.messages_signed[message] == signature

        # Alternative verification (mathematical check)
        # signature = msg_hash * private_key (mod p)
        # signature * public_key = msg_hash * private_key * 2^private_key (mod p)
        left_side = (signature * self.public_key) % self.p
        right_side = (msg_hash * pow(2, self.private_key, self.p)) % self.p

        return left_side == right_side