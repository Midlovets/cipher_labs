"""Алфавіти, з якими працює шифр Тритеміуса.

Потужність алфавіту n входить у формули шифрування:
    y = (x + k) mod n,    x = (y + n - (k mod n)) mod n
"""

from __future__ import annotations

UA_LETTERS = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"          # 33 літери
EN_LETTERS = "abcdefghijklmnopqrstuvwxyz"                    # 26 літер


class Alphabet:
    """Текстовий алфавіт. Регістр не впливає на індекс (А і а -> однаковий x),
    а символи поза алфавітом шифр залишає без змін.
    (Виняток — алфавіти з пробілом/апострофом: там результат завжди в нижньому регістрі.)"""

    def __init__(self, name: str, symbols: str):
        if len(set(symbols)) != len(symbols):
            raise ValueError("Символи алфавіту мають бути унікальними")
        self.name = name
        self.symbols = symbols
        self.n = len(symbols)
        # Регістр можна зберегти, лише якщо всі символи алфавіту — літери. Якщо в алфавіті є
        # пробіл чи апостроф, зашифрована літера може стати символом без регістру, і при
        # розшифруванні регістр був би втрачений, тому текст тоді приводиться до нижнього регістру.
        self.keeps_case = all(c.isalpha() for c in symbols)
        self._index = {c: i for i, c in enumerate(symbols)}

    def try_index(self, ch: str) -> int | None:
        """Індекс символу в алфавіті або None, якщо символу в алфавіті немає."""
        return self._index.get(ch.lower())

    def index(self, ch: str) -> int:
        i = self.try_index(ch)
        if i is None:
            raise ValueError(f"Символ {ch!r} відсутній в алфавіті «{self.name}»")
        return i

    def char(self, i: int) -> str:
        return self.symbols[i % self.n]

    def phrase_indices(self, phrase: str) -> list[int]:
        """Гасло -> список зсувів (номерів літер в алфавіті)."""
        return [self.index(c) for c in phrase]

    def phrase_from_indices(self, indices: list[int]) -> str:
        return "".join(self.char(i) for i in indices)

    def __repr__(self) -> str:
        return f"Alphabet({self.name!r}, n={self.n})"


class ByteAlphabet:
    """«Алфавіт» з 256 байтів — для шифрування довільних файлів."""

    name = "Байти (файли)"
    n = 256

    def phrase_indices(self, phrase: str) -> list[int]:
        return list(phrase.encode("utf-8"))

    def phrase_from_indices(self, indices: list[int]) -> str:
        return bytes(indices).decode("utf-8")

    def __repr__(self) -> str:
        return "ByteAlphabet(n=256)"


UKRAINIAN_33 = Alphabet("Українська (33)", UA_LETTERS)
# 33 літери + пробіл + апостроф = 35 символів
UKRAINIAN_35 = Alphabet("Українська (35: літери, пробіл, апостроф)", UA_LETTERS + " '")
ENGLISH_26 = Alphabet("English (26)", EN_LETTERS)
BYTES = ByteAlphabet()

TEXT_ALPHABETS = [UKRAINIAN_33, UKRAINIAN_35, ENGLISH_26]
