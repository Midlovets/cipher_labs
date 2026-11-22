# -*- coding: utf-8 -*-
"""
Власна (чиста Python) реалізація блокового шифру AES-128/192/256
(для виконання додаткового завдання лабораторної роботи).
"""

S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
INV_S_BOX = [0] * 256
for i, v in enumerate(S_BOX):
    INV_S_BOX[v] = i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result & 0xFF


def _sub_word(word):
    return [S_BOX[b] for b in word]


def _rot_word(word):
    return word[1:] + word[:1]


class AES:
    BLOCK_SIZE = 16
    KEY_SCHEDULE = {16: (4, 10), 24: (6, 12), 32: (8, 14)}

    def __init__(self, key: bytes):
        if len(key) not in self.KEY_SCHEDULE:
            raise ValueError("Ключ AES повинен мати довжину 16, 24 або 32 байти")
        self.Nk, self.Nr = self.KEY_SCHEDULE[len(key)]
        self._round_keys = self._key_expansion(key)

    def _key_expansion(self, key: bytes):
        Nk, Nr = self.Nk, self.Nr
        w = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
        for i in range(Nk, 4 * (Nr + 1)):
            temp = list(w[i - 1])
            if i % Nk == 0:
                temp = _sub_word(_rot_word(temp))
                temp[0] ^= RCON[i // Nk - 1]
            elif Nk > 6 and i % Nk == 4:
                temp = _sub_word(temp)
            w.append([a ^ b for a, b in zip(w[i - Nk], temp)])
        # групуємо по 4 слова (16 байт) на кожен раунд
        return [sum(w[4 * r:4 * r + 4], []) for r in range(Nr + 1)]

    @staticmethod
    def _add_round_key(state, round_key):
        return [[state[r][c] ^ round_key[4 * c + r] for c in range(4)] for r in range(4)]

    @staticmethod
    def _bytes_to_state(block):
        return [[block[4 * c + r] for c in range(4)] for r in range(4)]

    @staticmethod
    def _state_to_bytes(state):
        out = bytearray(16)
        for r in range(4):
            for c in range(4):
                out[4 * c + r] = state[r][c]
        return bytes(out)

    @staticmethod
    def _sub_bytes(state, box):
        return [[box[state[r][c]] for c in range(4)] for r in range(4)]

    @staticmethod
    def _shift_rows(state):
        return [state[r][r:] + state[r][:r] for r in range(4)]

    @staticmethod
    def _inv_shift_rows(state):
        return [state[r][-r:] + state[r][:-r] if r else state[r][:] for r in range(4)]

    @staticmethod
    def _mix_columns(state):
        new_state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            new_state[0][c] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
            new_state[1][c] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
            new_state[2][c] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
            new_state[3][c] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)
        return new_state

    @staticmethod
    def _inv_mix_columns(state):
        new_state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            new_state[0][c] = _mul(col[0], 14) ^ _mul(col[1], 11) ^ _mul(col[2], 13) ^ _mul(col[3], 9)
            new_state[1][c] = _mul(col[0], 9) ^ _mul(col[1], 14) ^ _mul(col[2], 11) ^ _mul(col[3], 13)
            new_state[2][c] = _mul(col[0], 13) ^ _mul(col[1], 9) ^ _mul(col[2], 14) ^ _mul(col[3], 11)
            new_state[3][c] = _mul(col[0], 11) ^ _mul(col[1], 13) ^ _mul(col[2], 9) ^ _mul(col[3], 14)
        return new_state

    def encrypt_block(self, block: bytes) -> bytes:
        state = self._bytes_to_state(block)
        state = self._add_round_key(state, self._round_keys[0])
        for rnd in range(1, self.Nr):
            state = self._sub_bytes(state, S_BOX)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self._round_keys[rnd])
        state = self._sub_bytes(state, S_BOX)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self._round_keys[self.Nr])
        return self._state_to_bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        state = self._bytes_to_state(block)
        state = self._add_round_key(state, self._round_keys[self.Nr])
        for rnd in range(self.Nr - 1, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._sub_bytes(state, INV_S_BOX)
            state = self._add_round_key(state, self._round_keys[rnd])
            state = self._inv_mix_columns(state)
        state = self._inv_shift_rows(state)
        state = self._sub_bytes(state, INV_S_BOX)
        state = self._add_round_key(state, self._round_keys[0])
        return self._state_to_bytes(state)


if __name__ == "__main__":
    # Офіційний тестовий вектор NIST FIPS-197, додаток C.1 (AES-128)
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    cipher = AES(key)
    ct = cipher.encrypt_block(pt)
    print("Зашифровано :", ct.hex())
    print("Очікувано   :", expected_ct.hex())
    assert ct == expected_ct, "Тест AES-128 НЕ пройдено!"
    assert cipher.decrypt_block(ct) == pt
    print("Тест AES-128 пройдено успішно.")
