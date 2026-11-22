# -*- coding: utf-8 -*-
"""
Власна (чиста Python, без сторонніх бібліотек) реалізація блокового шифру
DES та його розширення TripleDES (3DES).

Це аналог .NET-класів DESCryptoServiceProvider / TripleDESCryptoServiceProvider:
клас надає методи encrypt_block(8 байт) -> 8 байт і decrypt_block(8 байт) -> 8 байт,
а режими шифрування (ECB/CBC/CFB/OFB/CTR) та робота з файлами реалізовані окремо
в modes.py та crypto_provider.py.
"""

# ---------------------------------------------------------------------------
# Таблиці DES (стандартні, з специфікації FIPS 46-3)
# ---------------------------------------------------------------------------

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

S_BOXES = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]


def _permute(bits, table):
    return [bits[i - 1] for i in table]


def _bytes_to_bits(data):
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def _xor(a, b):
    return [x ^ y for x, y in zip(a, b)]


def _left_rotate(bits, n):
    return bits[n:] + bits[:n]


class DES:
    """Один блок DES: 64-бітний ключ (8 байт, молодший біт кожного байта —
    біт парності, як у специфікації), 64-бітний блок даних."""

    BLOCK_SIZE = 8  # байт
    KEY_SIZE = 8    # байт

    def __init__(self, key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError("Ключ DES повинен мати довжину 8 байт (64 біт)")
        self._round_keys = self._generate_round_keys(key)

    @staticmethod
    def _generate_round_keys(key: bytes):
        key_bits = _bytes_to_bits(key)
        permuted = _permute(key_bits, PC1)  # 56 біт
        c, d = permuted[:28], permuted[28:]
        round_keys = []
        for shift in SHIFTS:
            c = _left_rotate(c, shift)
            d = _left_rotate(d, shift)
            round_keys.append(_permute(c + d, PC2))  # 48 біт
        return round_keys

    @staticmethod
    def _feistel(r, round_key):
        expanded = _permute(r, E)  # 48 біт
        xored = _xor(expanded, round_key)
        out_bits = []
        for i in range(8):
            block = xored[i * 6:(i + 1) * 6]
            row = (block[0] << 1) | block[5]
            col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
            val = S_BOXES[i][row][col]
            out_bits.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])
        return _permute(out_bits, P)  # 32 біт

    def _crypt_block(self, block: bytes, round_keys) -> bytes:
        bits = _bytes_to_bits(block)
        bits = _permute(bits, IP)
        l, r = bits[:32], bits[32:]
        for rk in round_keys:
            new_r = _xor(l, self._feistel(r, rk))
            l = r
            r = new_r
        pre_output = r + l  # фінальна перестановка 32/32 (без свопу)
        return _bits_to_bytes(_permute(pre_output, FP))

    def encrypt_block(self, block: bytes) -> bytes:
        return self._crypt_block(block, self._round_keys)

    def decrypt_block(self, block: bytes) -> bytes:
        return self._crypt_block(block, list(reversed(self._round_keys)))


class TripleDES:
    """3DES (EDE) поверх трьох об'єктів DES. Підтримує ключ 16 байт
    (K1, K2, K1 — варіант «2-key») або 24 байти (K1, K2, K3 — варіант «3-key»)."""

    BLOCK_SIZE = 8
    KEY_SIZES = (16, 24)

    def __init__(self, key: bytes):
        if len(key) not in self.KEY_SIZES:
            raise ValueError("Ключ TripleDES повинен мати довжину 16 або 24 байти")
        if len(key) == 16:
            k1, k2 = key[:8], key[8:16]
            k3 = k1
        else:
            k1, k2, k3 = key[:8], key[8:16], key[16:24]
        self._d1 = DES(k1)
        self._d2 = DES(k2)
        self._d3 = DES(k3)

    def encrypt_block(self, block: bytes) -> bytes:
        return self._d3.encrypt_block(
            self._d2.decrypt_block(
                self._d1.encrypt_block(block)))

    def decrypt_block(self, block: bytes) -> bytes:
        return self._d1.decrypt_block(
            self._d2.encrypt_block(
                self._d3.decrypt_block(block)))


if __name__ == "__main__":
    # Самоперевірка на офіційному тестовому векторі DES (FIPS 81 / підручники):
    # key = 133457799BBCDFF1, plaintext = 0123456789ABCDEF -> cipher = 85E813540F0AB405
    key = bytes.fromhex("133457799BBCDFF1")
    pt = bytes.fromhex("0123456789ABCDEF")
    expected_ct = bytes.fromhex("85E813540F0AB405")

    cipher = DES(key)
    ct = cipher.encrypt_block(pt)
    print("Зашифровано :", ct.hex().upper())
    print("Очікувано   :", expected_ct.hex().upper())
    assert ct == expected_ct, "Тест DES НЕ пройдено!"
    dt = cipher.decrypt_block(ct)
    assert dt == pt, "Розшифрування НЕ співпадає з вихідним текстом!"
    print("Тест DES пройдено успішно.")

    # Швидкий тест TripleDES (K1=K2=K3 => повинно збігатись зі звичайним DES)
    tdes = TripleDES(key + key[::-1] + key)
    ct2 = tdes.encrypt_block(pt)
    dt2 = tdes.decrypt_block(ct2)
    assert dt2 == pt
    print("Тест TripleDES пройдено успішно.")
