"""Книжковий шифр — Лабораторна №3.

Реалізовано два різновиди:
  1. PoemCipher    — класичний «Віршований шифр»:
       Вірш записується у прямокутну таблицю рядок×стовпець.
       Кожній літері відкритого тексту ставиться у відповідність пара
       (рядок, стовпець) — RR/CC — будь-якого однакового символу з таблиці.
       Шифрограма: «RR/CC, RR/CC, ...»  (RR — рядок, CC — стовпець, 1-based).

  2. WordBookCipher — словесний варіант книжкового шифру:
       Кожна літера відкритого тексту замінюється на номер слова в ключовому
       тексті, що починається з тієї самої літери.
       Шифрограма: «42 7 103 ...»  (номери слів).
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
#  Загальне
# ---------------------------------------------------------------------------

class BookCipherError(ValueError):
    """Помилка книжкового шифру."""


# ---------------------------------------------------------------------------
#  1. Віршований шифр (PoemCipher)
# ---------------------------------------------------------------------------

class PoemCipher:
    """Шифрування/розшифрування на основі «віршової таблиці».

    Вірш нарізається на рядки рівно по *width* символів (зайві символи
    наприкінці рядка відкидаються, якщо trim_lines=True).
    Отримується прямокутна матриця rows x cols.

    Шифрограма — послідовність кодів виду «RR/CC» (1-based), відокремлених
    комами (та необов'язковими пробілами).

    Якщо символ відкритого тексту відсутній у таблиці, він записується
    у шифрограму як є (у кутових дужках), напр. «<,>» або «< >».
    """

    SEP = ", "
    _CODE_RE = re.compile(r"(\d+)/(\d+)")

    # Замінники для відсутніх букв (укр./рос.)
    _SUBSTITUTES: Dict[str, str] = {
        "щ": "ш", "ё": "е", "ъ": "ь", "э": "е",
    }

    def __init__(self, poem: str, width: int = 10, trim_lines: bool = True):
        """
        poem       — текст вірша
        width      — кількість символів у рядку таблиці (>=2)
        trim_lines — якщо True, зайві символи наприкінці відкидаються
        """
        if not poem or not poem.strip():
            raise BookCipherError("Вірш-ключ не може бути порожнім")
        if width < 2:
            raise BookCipherError("Ширина таблиці має бути не менше 2")

        self.width = width
        self.trim_lines = trim_lines
        self._table: List[str] = []
        self._build_table(poem)
        self._index: Dict[str, List[Tuple[int, int]]] = self._build_index()

    # -- побудова таблиці --------------------------------------------------

    def _build_table(self, poem: str) -> None:
        cleaned = re.sub(r"\r\n?|\n", " ", poem)
        if self.trim_lines:
            self._table = [
                cleaned[i: i + self.width]
                for i in range(0, len(cleaned), self.width)
                if len(cleaned[i: i + self.width]) == self.width
            ]
        else:
            self._table = [
                cleaned[i: i + self.width]
                for i in range(0, len(cleaned), self.width)
            ]
        if not self._table:
            raise BookCipherError("Вірш занадто короткий для заданої ширини таблиці")

    def _build_index(self) -> Dict[str, List[Tuple[int, int]]]:
        idx: Dict[str, List[Tuple[int, int]]] = {}
        for r, row in enumerate(self._table, start=1):
            for c, ch in enumerate(row, start=1):
                idx.setdefault(ch.lower(), []).append((r, c))
        return idx

    # -- публічні властивості ----------------------------------------------

    @property
    def rows(self) -> int:
        return len(self._table)

    @property
    def cols(self) -> int:
        return self.width

    @property
    def table(self) -> List[str]:
        return list(self._table)

    def available_chars(self) -> str:
        return "".join(sorted(self._index.keys()))

    def find_substitute(self, ch: str) -> Optional[str]:
        """Повертає замінник для символу (напр. щ->ш), або None."""
        return self._SUBSTITUTES.get(ch.lower())

    # -- шифрування --------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """Зашифрувати відкритий текст. Повертає шифрограму."""
        if not plaintext:
            raise BookCipherError("Текст для шифрування порожній")
        tokens: list[str] = []
        for ch in plaintext:
            lower = ch.lower()
            positions = self._index.get(lower)
            if positions is None:
                sub = self.find_substitute(lower)
                if sub:
                    positions = self._index.get(sub)
            if positions:
                r, c = random.choice(positions)
                tokens.append(f"{r}/{c}")
            else:
                tokens.append(f"<{ch}>")
        return self.SEP.join(tokens)

    # -- розшифрування -----------------------------------------------------

    def decrypt(self, ciphertext: str) -> str:
        """Розшифрувати шифрограму. Повертає відкритий текст."""
        if not ciphertext.strip():
            raise BookCipherError("Шифрограма порожня")
        tokens = [t.strip() for t in re.split(r",\s*", ciphertext.strip())]
        result: list[str] = []
        for token in tokens:
            if not token:
                continue
            m_lit = re.fullmatch(r"<(.)>", token)
            if m_lit:
                result.append(m_lit.group(1))
                continue
            m = self._CODE_RE.fullmatch(token)
            if not m:
                raise BookCipherError(
                    f"Некоректний токен: {token!r}. Очікується RR/CC або <символ>."
                )
            r, c = int(m.group(1)), int(m.group(2))
            if r < 1 or r > self.rows:
                raise BookCipherError(
                    f"Рядок {r} виходить за межі таблиці (1..{self.rows})"
                )
            if c < 1 or c > self.cols:
                raise BookCipherError(
                    f"Стовпець {c} виходить за межі таблиці (1..{self.cols})"
                )
            result.append(self._table[r - 1][c - 1])
        return "".join(result)

    # -- відображення ------------------------------------------------------

    def table_str(self, show_coords: bool = True) -> str:
        """Текстове зображення таблиці."""
        lines: list[str] = []
        if show_coords:
            header = "     " + "  ".join(f"{c:02d}" for c in range(1, self.cols + 1))
            lines.append(header)
            lines.append("     " + "----" * self.cols)
        for r, row in enumerate(self._table, start=1):
            cells = "  ".join(f" {ch} " for ch in row)
            if show_coords:
                lines.append(f"{r:02d} | {cells}")
            else:
                lines.append(cells)
        return "\n".join(lines)

    def describe(self) -> str:
        return f"Віршований шифр: таблиця {self.rows}x{self.cols}"


# ---------------------------------------------------------------------------
#  2. Словесний книжковий шифр (WordBookCipher) — додаткове завдання
# ---------------------------------------------------------------------------

@dataclass
class _WordEntry:
    index: int    # 1-based номер слова
    word: str     # оригінальне слово


class WordBookCipher:
    """Словесний різновид книжкового шифру (додаткове завдання).

    Ключовий текст розбивається на слова з нумерацією (1-based).
    Кожна літера відкритого тексту замінюється на номер слова у ключовому
    тексті, що починається з тієї ж літери (вибирається випадково серед
    усіх відповідних слів).

    Шифрограма: послідовність номерів, розділених пробілами.
    Пробіл у відкритому тексті кодується символом «_».
    Символ, для якого немає слова в ключі, кодується «<символ>».
    """

    def __init__(self, key_text: str):
        if not key_text or not key_text.strip():
            raise BookCipherError("Ключовий текст не може бути порожнім")
        self._entries: List[_WordEntry] = []
        self._letter_index: Dict[str, List[int]] = {}  # літера -> список 0-based індексів
        self._build(key_text)

    def _build(self, text: str) -> None:
        words = re.findall(r"\S+", text)
        if not words:
            raise BookCipherError("Ключовий текст не містить слів")
        for idx, w in enumerate(words, start=1):
            self._entries.append(_WordEntry(idx, w))
            first = w[0].lower()
            self._letter_index.setdefault(first, []).append(idx - 1)

    # -- шифрування --------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """Зашифрувати посимвольно."""
        if not plaintext:
            raise BookCipherError("Текст для шифрування порожній")
        tokens: list[str] = []
        for ch in plaintext:
            if ch == " ":
                tokens.append("_")
                continue
            if not ch.isalpha():
                tokens.append(f"<{ch}>")
                continue
            lower = ch.lower()
            candidates = self._letter_index.get(lower, [])
            if not candidates:
                tokens.append(f"<{ch}>")
            else:
                entry = self._entries[random.choice(candidates)]
                tokens.append(str(entry.index))
        return " ".join(tokens)

    # -- розшифрування -----------------------------------------------------

    def decrypt(self, ciphertext: str) -> str:
        """Розшифрувати."""
        if not ciphertext.strip():
            raise BookCipherError("Шифрограма порожня")
        tokens = ciphertext.strip().split()
        result: list[str] = []
        for token in tokens:
            if token == "_":
                result.append(" ")
                continue
            m_lit = re.fullmatch(r"<(.+?)>", token)
            if m_lit:
                result.append(m_lit.group(1))
                continue
            if not token.isdigit():
                raise BookCipherError(f"Некоректний токен: {token!r}")
            n = int(token)
            if n < 1 or n > len(self._entries):
                raise BookCipherError(
                    f"Номер слова {n} виходить за межі (1..{len(self._entries)})"
                )
            # Повертаємо першу літеру слова
            result.append(self._entries[n - 1].word[0])
        return "".join(result)

    def describe(self) -> str:
        return f"Словесний книжковий шифр: {len(self._entries)} слів у ключі"

    @property
    def key_size(self) -> int:
        return len(self._entries)
