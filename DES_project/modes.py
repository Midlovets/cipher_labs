# -*- coding: utf-8 -*-
"""
Реалізація режимів шифрування блокового шифру (аналог CipherMode у .NET:
ECB, CBC, CFB, OFB) плюс сучасний режим CTR.
Працює з будь-яким об'єктом шифру, що має BLOCK_SIZE, encrypt_block(), decrypt_block().
"""

import os

ALL_MODES = ["ECB", "CBC", "CFB", "OFB", "CTR"]

# Режими, яким потрібен вектор ініціалізації (IV); ECB — не потребує.
MODES_REQUIRING_IV = {"CBC", "CFB", "OFB", "CTR"}


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Некоректна довжина зашифрованих даних")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Некоректне доповнення (padding) — можливо, невірний ключ/IV")
    return data[:-pad_len]


def generate_random_bytes(n: int) -> bytes:
    return os.urandom(n)


def encrypt(cipher, mode: str, data: bytes, iv: bytes = None) -> bytes:
    """Шифрує дані блоковим шифром `cipher` у режимі `mode`.
    Повертає тільки шифротекст (IV, якщо потрібен, зберігається викликачем окремо)."""
    bs = cipher.BLOCK_SIZE
    mode = mode.upper()

    if mode in ("ECB", "CBC"):
        data = pkcs7_pad(data, bs)

    blocks = [data[i:i + bs] for i in range(0, len(data), bs)]
    out = bytearray()

    if mode == "ECB":
        for b in blocks:
            out += cipher.encrypt_block(b)

    elif mode == "CBC":
        prev = iv
        for b in blocks:
            x = _xor_bytes(b, prev)
            enc = cipher.encrypt_block(x)
            out += enc
            prev = enc

    elif mode == "CFB":
        prev = iv
        for b in blocks:
            keystream = cipher.encrypt_block(prev)
            enc = _xor_bytes(b, keystream[:len(b)])
            out += enc
            prev = enc

    elif mode == "OFB":
        feedback = iv
        for b in blocks:
            feedback = cipher.encrypt_block(feedback)
            out += _xor_bytes(b, feedback[:len(b)])

    elif mode == "CTR":
        counter = int.from_bytes(iv, "big")
        for b in blocks:
            counter_bytes = (counter % (1 << (bs * 8))).to_bytes(bs, "big")
            keystream = cipher.encrypt_block(counter_bytes)
            out += _xor_bytes(b, keystream[:len(b)])
            counter += 1

    else:
        raise ValueError(f"Невідомий режим шифрування: {mode}")

    return bytes(out)


def decrypt(cipher, mode: str, data: bytes, iv: bytes = None) -> bytes:
    bs = cipher.BLOCK_SIZE
    mode = mode.upper()
    blocks = [data[i:i + bs] for i in range(0, len(data), bs)]
    out = bytearray()

    if mode == "ECB":
        for b in blocks:
            out += cipher.decrypt_block(b)
        return pkcs7_unpad(bytes(out), bs)

    elif mode == "CBC":
        prev = iv
        for b in blocks:
            dec = cipher.decrypt_block(b)
            out += _xor_bytes(dec, prev)
            prev = b
        return pkcs7_unpad(bytes(out), bs)

    elif mode == "CFB":
        prev = iv
        for b in blocks:
            keystream = cipher.encrypt_block(prev)
            out += _xor_bytes(b, keystream[:len(b)])
            prev = b
        return bytes(out)

    elif mode == "OFB":
        feedback = iv
        for b in blocks:
            feedback = cipher.encrypt_block(feedback)
            out += _xor_bytes(b, feedback[:len(b)])
        return bytes(out)

    elif mode == "CTR":
        counter = int.from_bytes(iv, "big")
        for b in blocks:
            counter_bytes = (counter % (1 << (bs * 8))).to_bytes(bs, "big")
            keystream = cipher.encrypt_block(counter_bytes)
            out += _xor_bytes(b, keystream[:len(b)])
            counter += 1
        return bytes(out)

    else:
        raise ValueError(f"Невідомий режим шифрування: {mode}")
