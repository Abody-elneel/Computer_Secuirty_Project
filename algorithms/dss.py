
import random
import hashlib


class DSS:
    """Digital Signature Scheme (Simplified)"""

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.p = 61  # Small prime

    def generate_keys(self):
        """Generate DSS keys"""
        self.private_key = random.randint(2, self.p - 2)
        self.public_key = pow(2, self.private_key, self.p)
        return {"public_key": self.public_key, "private_key": self.private_key}

    def sign(self, message):
        """Sign message"""
        if not self.private_key:
            self.generate_keys()
        msg_hash = int(hashlib.md5(message.encode()).hexdigest(), 16)
        signature = (msg_hash * self.private_key) % self.p
        return signature

    def verify(self, message, signature):
        """Verify signature"""
        if not self.public_key:
            return False
        msg_hash = int(hashlib.md5(message.encode()).hexdigest(), 16)
        return (signature * self.public_key) % self.p == msg_hash % self.p