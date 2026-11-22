# -*- coding: utf-8 -*-
"""
CryptoProvider — аналог пари класів .NET (CryptographicServiceProvider + CryptoStream):
дозволяє динамічно обрати один з трьох алгоритмів — DES, TripleDES або AES —
та один з режимів шифрування, після чого шифрувати/розшифровувати як байти в
пам'яті, так і файли (через файлові потоки, подібно до FileStream у лістингу
роботи).
"""

from des import DES, TripleDES
from aes import AES
import modes

ALGORITHMS = {
    "DES": {"cls": DES, "key_sizes": [8]},
    "TripleDES": {"cls": TripleDES, "key_sizes": [16, 24]},
    "AES": {"cls": AES, "key_sizes": [16, 24, 32]},
}


def default_key_size(algorithm: str) -> int:
    return ALGORITHMS[algorithm]["key_sizes"][0]


def block_size_of(algorithm: str) -> int:
    return 16 if algorithm == "AES" else 8


def normalize_key(algorithm: str, raw_key: bytes) -> bytes:
    """Приводить довільний ключ користувача (ASCII/UTF-8) до допустимої довжини
    для обраного алгоритму: обрізає або доповнює нулями до найближчого
    підтримуваного розміру ключа (не менше мінімального)."""
    sizes = ALGORITHMS[algorithm]["key_sizes"]
    target = next((s for s in sizes if s >= len(raw_key)), sizes[-1])
    if len(raw_key) >= target:
        return raw_key[:target]
    return raw_key + b"\x00" * (target - len(raw_key))


class CryptoProvider:
    """Єдина точка входу: обирається алгоритм (DES/TripleDES/AES) і режим
    (ECB/CBC/CFB/OFB/CTR), далі провайдер шифрує/розшифровує байти або файли."""

    def __init__(self, algorithm: str, mode: str, key: bytes, iv: bytes = None):
        if algorithm not in ALGORITHMS:
            raise ValueError(f"Невідомий алгоритм: {algorithm}")
        if mode.upper() not in modes.ALL_MODES:
            raise ValueError(f"Невідомий режим: {mode}")

        self.algorithm = algorithm
        self.mode = mode.upper()
        bs = block_size_of(algorithm)

        if self.mode in modes.MODES_REQUIRING_IV:
            if iv is None:
                raise ValueError("Для цього режиму необхідний вектор ініціалізації (IV)")
            if len(iv) != bs:
                raise ValueError(f"IV повинен мати довжину {bs} байт для {algorithm}")
        self.iv = iv

        cls = ALGORITHMS[algorithm]["cls"]
        self._cipher = cls(key)

    # ---------- шифрування/розшифрування блоку даних у пам'яті ----------

    def encrypt_bytes(self, data: bytes) -> bytes:
        return modes.encrypt(self._cipher, self.mode, data, self.iv)

    def decrypt_bytes(self, data: bytes) -> bytes:
        return modes.decrypt(self._cipher, self.mode, data, self.iv)

    # ---------- шифрування/розшифрування файлів (файлові потоки) ----------
    # Аналог кроків лістингу: FileStream -> CryptoStream -> запис/читання байтів.

    def encrypt_file(self, in_path: str, out_path: str) -> None:
        with open(in_path, "rb") as fs_in:
            data = fs_in.read()
        encrypted = self.encrypt_bytes(data)
        with open(out_path, "wb") as fs_out:
            fs_out.write(encrypted)

    def decrypt_file(self, in_path: str, out_path: str) -> None:
        with open(in_path, "rb") as fs_in:
            data = fs_in.read()
        decrypted = self.decrypt_bytes(data)
        with open(out_path, "wb") as fs_out:
            fs_out.write(decrypted)


if __name__ == "__main__":
    # Невеличкий інтеграційний тест усіх алгоритмів і всіх режимів.
    import os

    text = "Привіт, світ! Hello world! 123-456".encode("utf-8")

    for algo in ALGORITHMS:
        key = normalize_key(algo, os.urandom(32))
        for mode_name in modes.ALL_MODES:
            iv = os.urandom(block_size_of(algo)) if mode_name in modes.MODES_REQUIRING_IV else None
            provider = CryptoProvider(algo, mode_name, key, iv)
            ct = provider.encrypt_bytes(text)
            provider2 = CryptoProvider(algo, mode_name, key, iv)  # окремий екземпляр, як при розшифруванні
            pt = provider2.decrypt_bytes(ct)
            status = "OK" if pt == text else "FAIL"
            print(f"{algo:10s} {mode_name:4s} -> {status} (ciphertext {len(ct)} байт)")
            assert pt == text
    print("Усі комбінації алгоритм/режим пройшли перевірку.")
