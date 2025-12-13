
import random


class SDES:
    """Simplified DES Implementation"""

    def __init__(self):
        self.key = None

    def generate_key(self):
        """Generate 8-bit key"""
        self.key = format(random.randint(0, 255), '08b')
        return self.key

    def _parity_drop(self, key):
        """Drop parity bits from 10-bit key to 8-bit"""
        parity_drop_table = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        return ''.join(key[i - 1] for i in parity_drop_table)

    def _circular_shift(self, half, shift_amount):
        """Perform circular left shift"""
        return half[shift_amount:] + half[:shift_amount]

    def _sbox_lookup(self, bits, sbox):
        """Lookup value in S-box"""
        row = int(bits[0] + bits[3], 2)
        col = int(bits[1] + bits[2], 2)
        return format(sbox[row][col], '02b')

    def encrypt(self, plaintext):
        """Encrypt plaintext using SDES"""
        if not self.key:
            self.generate_key()

        # Pad plaintext to multiple of 1 byte
        plaintext_padded = plaintext + ' ' * (1 - len(plaintext) % 1)
        ciphertext = ""

        for char in plaintext:
            block = format(ord(char), '08b')
            encrypted_block = self._encrypt_block(block)
            ciphertext += encrypted_block

        return ciphertext

    def _encrypt_block(self, block):
        """Encrypt single 8-bit block"""
        # Initial Permutation
        ip_table = [2, 6, 3, 1, 4, 8, 5, 7]
        ip_block = ''.join(block[i - 1] for i in ip_table)

        # Split
        L = ip_block[:4]
        R = ip_block[4:]

        # Round 1
        R_expanded = R[3] + R[0] + R[1] + R[2]  # Simple expansion
        subkey1 = self.key[:4]
        xor_result = ''.join(str(int(R_expanded[i]) ^ int(subkey1[i])) for i in range(4))

        s_box1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
        s_box2 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

        s_result = self._sbox_lookup(xor_result[:4], s_box1) + self._sbox_lookup(
            xor_result[4:8] if len(xor_result) > 4 else xor_result[:4], s_box2)

        # Permutation
        p_table = [2, 4, 3, 1]
        p_result = ''.join(s_result[i - 1] for i in p_table)

        # XOR with L
        new_R = ''.join(str(int(L[i]) ^ int(p_result[i])) for i in range(4))

        # Swap
        combined = new_R + R

        # Final Permutation
        final_table = [4, 1, 3, 5, 7, 2, 8, 6]
        ciphertext = ''.join(combined[i - 1] for i in final_table)

        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypt ciphertext using SDES"""
        if not self.key:
            return "No key generated"

        plaintext = ""
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i + 8]
            if len(block) == 8:
                decrypted_block = self._decrypt_block(block)
                plaintext += decrypted_block

        return plaintext.strip()

    def _decrypt_block(self, block):
        """Decrypt single block"""
        # Inverse Final Permutation
        inv_final_table = [2, 6, 3, 1, 7, 8, 5, 4]
        block = ''.join(block[i - 1] for i in inv_final_table)

        # Reverse the encryption process
        L = block[:4]
        R = block[4:]

        # Reverse operations (simplified for SDES)
        ip_table = [2, 6, 3, 1, 4, 8, 5, 7]
        inv_ip = [4, 1, 3, 5, 7, 2, 8, 6]

        result = ''.join(block[i - 1] for i in inv_ip)

        return result