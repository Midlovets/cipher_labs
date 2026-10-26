"""Ключі шифру Тритеміуса та їх валідація.

Крок зміщення k для символу на позиції p:
    LinearKey    : k = A*p + B
    QuadraticKey : k = A*p^2 + B*p + C
    PhraseKey    : k = номер в алфавіті літери гасла, яке циклічно повторюється під текстом
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class InvalidKeyError(ValueError):
    """Ключ не пройшов валідацію."""


def _check_int(name: str, value) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidKeyError(f"Коефіцієнт {name} має бути цілим числом, отримано {value!r}")


class Key(ABC):
    kind: str = ""

    @abstractmethod
    def validate(self, alphabet) -> None:
        """Кидає InvalidKeyError, якщо ключ непридатний для даного алфавіту."""

    @abstractmethod
    def shift(self, p: int, t: int, alphabet) -> int:
        """Крок зміщення k.

        p — позиція літери (з урахуванням обраної нумерації: з 0 або з 1),
        t — порядковий номер літери в повідомленні, завжди з 0 (для гасла).
        """

    @abstractmethod
    def describe(self) -> str:
        ...


class LinearKey(Key):
    """k = A*p + B  — 2-вимірний вектор ключа (A, B)."""

    kind = "linear"

    def __init__(self, A: int, B: int):
        self.A, self.B = A, B

    def validate(self, alphabet) -> None:
        _check_int("A", self.A)
        _check_int("B", self.B)
        n = alphabet.n
        if self.A % n == 0 and self.B % n == 0:
            raise InvalidKeyError(
                f"Ключ (A={self.A}, B={self.B}) дає нульовий зсув за модулем {n}: текст не зміниться"
            )

    def shift(self, p: int, t: int, alphabet) -> int:
        return (self.A * p + self.B) % alphabet.n

    def describe(self) -> str:
        return f"лінійний: k = {self.A}·p + {self.B}"

    def __eq__(self, other):
        return isinstance(other, LinearKey) and (self.A, self.B) == (other.A, other.B)

    def __repr__(self):
        return f"LinearKey(A={self.A}, B={self.B})"


class QuadraticKey(Key):
    """k = A*p^2 + B*p + C  — 3-вимірний вектор ключа (A, B, C)."""

    kind = "quadratic"

    def __init__(self, A: int, B: int, C: int):
        self.A, self.B, self.C = A, B, C

    def validate(self, alphabet) -> None:
        _check_int("A", self.A)
        _check_int("B", self.B)
        _check_int("C", self.C)
        n = alphabet.n
        if self.A % n == 0 and self.B % n == 0 and self.C % n == 0:
            raise InvalidKeyError(
                f"Ключ (A={self.A}, B={self.B}, C={self.C}) дає нульовий зсув за модулем {n}"
            )

    def shift(self, p: int, t: int, alphabet) -> int:
        return (self.A * p * p + self.B * p + self.C) % alphabet.n

    def describe(self) -> str:
        return f"нелінійний: k = {self.A}·p² + {self.B}·p + {self.C}"

    def __eq__(self, other):
        return isinstance(other, QuadraticKey) and (self.A, self.B, self.C) == (other.A, other.B, other.C)

    def __repr__(self):
        return f"QuadraticKey(A={self.A}, B={self.B}, C={self.C})"


class PhraseKey(Key):
    """Гасло — текстовий рядок, що циклічно записується під повідомленням."""

    kind = "phrase"

    def __init__(self, phrase: str):
        self.phrase = phrase
        self._cache: dict[int, list[int]] = {}   # id(алфавіту) -> індекси літер гасла

    def _indices(self, alphabet) -> list[int]:
        key = id(alphabet)
        if key not in self._cache:
            self._cache[key] = alphabet.phrase_indices(self.phrase)
        return self._cache[key]

    def validate(self, alphabet) -> None:
        if not isinstance(self.phrase, str) or not self.phrase:
            raise InvalidKeyError("Гасло не може бути порожнім")
        try:
            indices = alphabet.phrase_indices(self.phrase)
        except ValueError:
            bad = sorted({c for c in self.phrase if getattr(alphabet, "try_index", lambda _c: 0)(c) is None})
            raise InvalidKeyError(
                f"Гасло містить символи, яких немає в алфавіті «{alphabet.name}»: {' '.join(map(repr, bad))}"
            ) from None
        if all(i % alphabet.n == 0 for i in indices):
            raise InvalidKeyError("Гасло складається лише з першої літери алфавіту: зсув завжди нульовий")

    def shift(self, p: int, t: int, alphabet) -> int:
        indices = self._indices(alphabet)
        return indices[t % len(indices)] % alphabet.n

    def describe(self) -> str:
        return f"гасло: «{self.phrase}»"

    def __eq__(self, other):
        return isinstance(other, PhraseKey) and self.phrase.lower() == other.phrase.lower()

    def __repr__(self):
        return f"PhraseKey({self.phrase!r})"
