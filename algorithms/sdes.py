import random


class SDES:
    """Simplified DES Implementation - Proper Working Version"""

    def __init__(self):
        self.key = None
        self.k1 = None
        self.k2 = None

    def generate_key(self):
        """Generate 10-bit key"""
        key_10bit = format(random.randint(0, 1023), '010b')
        self.key = key_10bit
        self._generate_subkeys()
        return self.key

    def _generate_subkeys(self):
        """Generate two 8-bit subkeys from 10-bit key"""
        # Permutation 10 (PC-1 for SDES)
        pc10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]

        # Permutation 8 (PC-2 for SDES)
        pc8 = [6, 3, 7, 4, 8, 5, 10, 9]

        # Apply PC-1
        permuted = ''.join(self.key[i - 1] for i in pc10)

        # Split into left (L0) and right (R0) - 5 bits each
        L = permuted[:5]
        R = permuted[5:]

        # Left shift both by 1 for first subkey
        L1 = L[1:] + L[0]
        R1 = R[1:] + R[0]
        combined1 = L1 + R1
        self.k1 = ''.join(combined1[i - 1] for i in pc8)

        # Left shift both by 2 more for second subkey
        L2 = L1[2:] + L1[:2]
        R2 = R1[2:] + R1[:2]
        combined2 = L2 + R2
        self.k2 = ''.join(combined2[i - 1] for i in pc8)

    def _ip(self, block):
        """Initial permutation"""
        ip_table = [2, 6, 3, 1, 4, 8, 5, 7]
        return ''.join(block[i - 1] for i in ip_table)

    def _ip_inv(self, block):
        """Inverse initial permutation"""
        ip_inv_table = [4, 1, 3, 5, 7, 2, 8, 6]
        return ''.join(block[i - 1] for i in ip_inv_table)

    def _expand(self, right):
        """Expansion box (4 bits -> 8 bits)"""
        expand_table = [4, 1, 2, 3, 2, 3, 4, 1]
        return ''.join(right[i - 1] for i in expand_table)

    def _sbox(self, bits, sbox_num):
        """S-box substitution"""
        s_boxes = [
            # S0
            [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]],
            # S1
            [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]
        ]

        row = int(bits[0] + bits[3], 2)
        col = int(bits[1] + bits[2], 2)
        return format(s_boxes[sbox_num][row][col], '02b')

    def _permutation(self, bits):
        """P-box permutation"""
        p_table = [2, 4, 3, 1]
        return ''.join(bits[i - 1] for i in p_table)

    def _f(self, right, subkey):
        """F-function"""
        # Expand right from 4 to 8 bits
        expanded = self._expand(right)

        # XOR with subkey
        xored = ''.join(str(int(expanded[i]) ^ int(subkey[i])) for i in range(8))

        # S-box substitution
        s0_in = xored[:4]
        s1_in = xored[4:]
        s0_out = self._sbox(s0_in, 0)
        s1_out = self._sbox(s1_in, 1)
        sbox_out = s0_out + s1_out

        # P-box permutation
        return self._permutation(sbox_out)

    def _round(self, left, right, subkey):
        """One encryption round"""
        f_out = self._f(right, subkey)
        new_left = right
        new_right = ''.join(str(int(left[i]) ^ int(f_out[i])) for i in range(4))
        return new_left, new_right

    def encrypt(self, plaintext):
        """Encrypt plaintext"""
        if not self.key:
            self.generate_key()

        ciphertext_hex = ""

        for char in plaintext:
            block = format(ord(char), '08b')

            # Initial permutation
            permuted = self._ip(block)

            left = permuted[:4]
            right = permuted[4:]

            # Round 1
            left, right = self._round(left, right, self.k1)

            # Round 2
            left, right = self._round(left, right, self.k2)

            # Combine (swap for SDES)
            combined = right + left

            # Inverse permutation
            encrypted = self._ip_inv(combined)

            ciphertext_hex += encrypted

        return ciphertext_hex

    def decrypt(self, ciphertext_bin):
        """Decrypt ciphertext"""
        if not self.key:
            return "No key generated"

        plaintext = ""

        for i in range(0, len(ciphertext_bin), 8):
            block = ciphertext_bin[i:i + 8]
            if len(block) == 8:
                # Initial permutation
                permuted = self._ip(block)

                left = permuted[:4]
                right = permuted[4:]

                # Round 1 (use k2 for decryption)
                left, right = self._round(left, right, self.k2)

                # Round 2 (use k1 for decryption)
                left, right = self._round(left, right, self.k1)

                # Combine (swap for SDES)
                combined = right + left

                # Inverse permutation
                decrypted = self._ip_inv(combined)

                plaintext += chr(int(decrypted, 2))

        return plaintext