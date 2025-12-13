import random


class RSA:
    """RSA Implementation"""

    def __init__(self):
        self.p = None
        self.q = None
        self.n = None
        self.phi = None
        self.e = None
        self.d = None

    def is_prime(self, num, k=5):
        """Miller-Rabin primality test"""
        if num < 2:
            return False
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
            if num == p:
                return True
            if num % p == 0:
                return False
        return True

    def generate_keys(self, p=None, q=None):
        """Generate RSA keys"""
        if not p or not q:
            primes = [61, 53, 47, 43, 41, 37, 31, 29, 23, 19, 17, 13, 11, 7, 5, 3, 2]
            self.p = random.choice(primes[:5])
            self.q = random.choice(primes[5:10])
        else:
            self.p = p
            self.q = q

        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)

        # Select e
        for e in range(2, self.phi):
            if self.gcd(e, self.phi) == 1:
                self.e = e
                break

        # Calculate d
        self.d = self._mod_inverse(self.e, self.phi)

        return {"n": self.n, "e": self.e, "d": self.d, "p": self.p, "q": self.q}

    def gcd(self, a, b):
        """Greatest Common Divisor"""
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, e, phi):
        """Extended Euclidean Algorithm to find modular inverse"""
        for d in range(1, phi):
            if (e * d) % phi == 1:
                return d
        return None

    def encrypt(self, plaintext):
        """Encrypt text message"""
        if not self.e or not self.n:
            return "Keys not generated"

        try:
            # Convert text to numbers (encrypt each character)
            ciphertext_list = []
            for char in str(plaintext):
                m = ord(char)
                if m >= self.n:
                    return f"Error: Character '{char}' (value {m}) is too large for modulus {self.n}"
                c = pow(m, self.e, self.n)
                ciphertext_list.append(str(c))

            return ','.join(ciphertext_list)
        except Exception as e:
            return f"Encryption error: {str(e)}"

    def decrypt(self, ciphertext):
        """Decrypt message"""
        if not self.d or not self.n:
            return "Keys not generated"

        try:
            # Split the ciphertext by commas
            if ',' not in str(ciphertext):
                return "Error: Invalid ciphertext format. Expected comma-separated values."

            ciphertext_list = str(ciphertext).split(',')
            plaintext = ""

            for cipher_val in ciphertext_list:
                cipher_val = cipher_val.strip()
                if not cipher_val.isdigit():
                    return f"Error: Invalid cipher value '{cipher_val}'"

                c = int(cipher_val)
                m = pow(c, self.d, self.n)
                plaintext += chr(m)

            return plaintext
        except Exception as e:
            return f"Decryption error: {str(e)}"