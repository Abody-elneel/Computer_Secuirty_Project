import ecdsa as ecd
import hashlib as hash


class DSS:
    """Digital Signature Scheme using ECDSA with SECP256k1 curve"""

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.messages_signed = {}

    def generate_keys(self):
        """Generate ECDSA keys using SECP256k1 curve"""
        # Generate private key
        self.private_key = ecd.SigningKey.generate(curve=ecd.SECP256k1)

        # Derive public key from private key
        self.public_key = self.private_key.get_verifying_key()

        # Reset signature storage
        self.messages_signed = {}

        return {
            "public_key": self.public_key.to_string().hex(),
            "private_key": self.private_key.to_string().hex()
        }

    def sign(self, message):
        """Sign message with private key"""
        if not self.private_key:
            self.generate_keys()

        # Encode message and create SHA-1 hash
        message_encoded = message.encode('utf-8')
        message_hash = hash.sha1(message_encoded).digest()

        # Sign the message hash with private key
        signature = self.private_key.sign(message_hash)

        # Store the message-signature pair for verification
        self.messages_signed[message] = signature

        # Return signature as hex string
        return signature.hex()

    def verify(self, message, signature):
        """Verify signature with public key"""
        if not self.public_key:
            return False

        try:
            # Convert hex signature back to bytes
            if isinstance(signature, str):
                signature_bytes = bytes.fromhex(signature)
            else:
                signature_bytes = signature

            # Encode message and create SHA-1 hash (same as signing process)
            message_encoded = message.encode('utf-8')
            message_hash = hash.sha1(message_encoded).digest()

            # Verify the signature
            self.public_key.verify(signature_bytes, message_hash)
            return True

        except ecd.BadSignatureError:
            return False
        except Exception:
            return False