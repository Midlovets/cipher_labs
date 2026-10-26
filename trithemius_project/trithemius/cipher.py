"""Шифр Тритеміуса: шифрування, розшифрування та валідація.

    шифрування:    y = (x + k) mod n
    розшифрування: x = (y + n - (k mod n)) mod n

Для тексту позиція p рахується лише по літерах алфавіту (пробіли, цифри, розділові
знаки, що не входять в алфавіт, лишаються як є і позицію не збільшують).
Регістр літер зберігається (крім алфавітів з пробілом/апострофом — там усе в нижньому регістрі).
"""

from __future__ import annotations

from dataclasses import dataclass

from .alphabet import Alphabet, ByteAlphabet
from .keys import InvalidKeyError, Key


class InvalidDataError(ValueError):
    """Вхідні дані не пройшли валідацію."""


@dataclass
class ValidationResult:
    ok: bool
    message: str

    def __bool__(self) -> bool:
        return self.ok


class TrithemiusCipher:
    def __init__(self, alphabet, key: Key, first_position: int = 0):
        """first_position — з якого числа нумеруються позиції літер (0 або 1)."""
        if first_position not in (0, 1):
            raise ValueError("Нумерація позицій може починатися лише з 0 або з 1")
        key.validate(alphabet)          # валідація ключа
        self.alphabet = alphabet
        self.key = key
        self.first_position = first_position

    # ---------- валідація даних ----------

    def validate_text(self, text: str) -> None:
        """Перевіряє, що текст придатний для шифрування/розшифрування."""
        if not isinstance(self.alphabet, Alphabet):
            raise InvalidDataError("Для текстових даних потрібен текстовий алфавіт")
        if not isinstance(text, str) or not text.strip():
            raise InvalidDataError("Текст порожній")
        if not any(self.alphabet.try_index(c) is not None for c in text):
            raise InvalidDataError(
                f"У тексті немає жодної літери алфавіту «{self.alphabet.name}» — шифрувати нічого"
            )

    def validate_bytes(self, data: bytes) -> None:
        if not isinstance(self.alphabet, ByteAlphabet):
            raise InvalidDataError("Для байтових даних потрібен ByteAlphabet")
        if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
            raise InvalidDataError("Дані порожні")

    def validate_encryption(self, plain: str, encrypted: str) -> ValidationResult:
        """Перевіряє, що `encrypted` справді є коректним шифруванням `plain` цим ключем."""
        return self._compare(plain, encrypted, self.encrypt_text(plain), "шифрування")

    def validate_decryption(self, encrypted: str, decrypted: str) -> ValidationResult:
        """Перевіряє, що `decrypted` справді є коректним розшифруванням `encrypted`."""
        return self._compare(encrypted, decrypted, self.decrypt_text(encrypted), "розшифрування")

    @staticmethod
    def _compare(source: str, result: str, expected: str, what: str) -> ValidationResult:
        if len(source) != len(result):
            return ValidationResult(False, f"Довжина не збігається ({len(source)} ≠ {len(result)}) — {what} некоректне")
        if result != expected:
            pos = next(i for i, (a, b) in enumerate(zip(result, expected)) if a != b)
            return ValidationResult(False, f"{what.capitalize()} некоректне: перша розбіжність на символі №{pos + 1}")
        return ValidationResult(True, f"{what.capitalize()} коректне")

    def round_trip_ok(self, text: str) -> bool:
        """decrypt(encrypt(text)) == text."""
        return self.decrypt_text(self.encrypt_text(text)) == text

    # ---------- текст ----------

    def _transform_text(self, text: str, direction: int) -> str:
        self.validate_text(text)
        alphabet, n = self.alphabet, self.alphabet.n
        out: list[str] = []
        t = 0
        for ch in text:
            x = alphabet.try_index(ch)
            if x is None:
                out.append(ch)
                continue
            k = self.key.shift(t + self.first_position, t, alphabet)
            if direction > 0:
                y = (x + k) % n
            else:
                y = (x + n - (k % n)) % n
            c = alphabet.char(y)
            out.append(c.upper() if ch.isupper() and alphabet.keeps_case else c)
            t += 1
        return "".join(out)

    def encrypt_text(self, text: str) -> str:
        return self._transform_text(text, +1)

    def decrypt_text(self, text: str) -> str:
        return self._transform_text(text, -1)

    # ---------- довільні файли (байти) ----------

    def _transform_bytes(self, data: bytes, direction: int) -> bytes:
        self.validate_bytes(data)
        alphabet, n = self.alphabet, self.alphabet.n
        key, f = self.key, self.first_position
        out = bytearray(len(data))
        for t, x in enumerate(data):
            k = key.shift(t + f, t, alphabet)
            out[t] = (x + k) % n if direction > 0 else (x + n - (k % n)) % n
        return bytes(out)

    def encrypt_bytes(self, data: bytes) -> bytes:
        return self._transform_bytes(data, +1)

    def decrypt_bytes(self, data: bytes) -> bytes:
        return self._transform_bytes(data, -1)
