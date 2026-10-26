"""Активна атака на шифр Тритеміуса: відома пара «відкритий текст – шифртекст».

Ідея. З пари (x_t, y_t) одразу отримуємо кроки зміщення
        s_t = (y_t - x_t) mod n .
Далі перевіряємо, яка модель кроку їх породжує:
  * лінійна     s = A*p + B          — A, B знаходимо з двох перших літер, решту перевіряємо;
  * нелінійна   s = A*p^2 + B*p + C  — з трьох перших літер (різниці), решту перевіряємо;
  * гасло       s_t = s_{t+L}        — шукаємо найменший період L, перші L зсувів і є гасло.

Ключ визначається з точністю до модуля n: (A, B) і (A + n, B) — один і той самий ключ.
Якщо n парне, у нелінійного ключа можуть існувати кілька різних трійок, що дають
однакове шифрування — тоді повертаються всі кандидати.
"""

from __future__ import annotations

from dataclasses import dataclass

from .alphabet import Alphabet, ByteAlphabet
from .keys import Key, LinearKey, PhraseKey, QuadraticKey


class AttackError(ValueError):
    """Атаку неможливо виконати з наданими даними."""


@dataclass
class AttackResult:
    kind: str                 # "linear" | "quadratic" | "phrase"
    key: Key | None           # знайдений ключ (None, якщо гасло не вдалося подати як текст)
    reliable: bool            # чи достатньо даних, щоб вважати результат однозначним
    note: str = ""

    def __str__(self) -> str:
        head = self.key.describe() if self.key is not None else "гасло (байти, не UTF-8)"
        mark = "" if self.reliable else "  [ненадійно]"
        return f"{head}{mark}" + (f"\n    {self.note}" if self.note else "")


# ---------- крок 1: отримання зсувів ----------

def extract_shifts(alphabet, plain, cipher) -> list[int]:
    """Повертає s_t = (y_t - x_t) mod n для всіх літер алфавіту."""
    if len(plain) != len(cipher):
        raise AttackError(
            f"Довжини не збігаються ({len(plain)} ≠ {len(cipher)}): це не пара «текст – його шифрування»"
        )
    n = alphabet.n
    shifts: list[int] = []
    if isinstance(alphabet, ByteAlphabet):
        return [(y - x) % n for x, y in zip(plain, cipher)]
    for i, (a, b) in enumerate(zip(plain, cipher)):
        x, y = alphabet.try_index(a), alphabet.try_index(b)
        if x is None and y is None:
            if a != b:
                raise AttackError(f"Символ №{i + 1}: {a!r} ≠ {b!r}, а шифр не змінює символи поза алфавітом")
            continue
        if x is None or y is None:
            raise AttackError(f"Символ №{i + 1}: літера алфавіту відповідає символу поза алфавітом")
        if alphabet.keeps_case and a.isupper() != b.isupper():
            raise AttackError(f"Символ №{i + 1}: регістр у парі не збігається")
        shifts.append((y - x) % n)
    return shifts


# ---------- крок 2: моделі ----------

def attack_linear(shifts: list[int], n: int, first_position: int = 0) -> list[LinearKey]:
    if len(shifts) < 2:
        raise AttackError("Для лінійного ключа потрібно щонайменше 2 літери")
    f = first_position
    A = (shifts[1] - shifts[0]) % n
    B = (shifts[0] - A * f) % n
    if all((A * (f + t) + B) % n == s for t, s in enumerate(shifts)):
        return [LinearKey(A, B)]
    return []


def attack_quadratic(shifts: list[int], n: int, first_position: int = 0) -> list[QuadraticKey]:
    if len(shifts) < 3:
        raise AttackError("Для нелінійного ключа потрібно щонайменше 3 літери")
    f = first_position
    s0, s1, s2 = shifts[:3]
    d2 = (s2 - 2 * s1 + s0) % n               # = 2A (mod n)
    found: list[QuadraticKey] = []
    for A in range(n):                       # якщо n парне, 2A ≡ d2 може мати 0 або 2 розв'язки
        if (2 * A) % n != d2:
            continue
        B = (s1 - s0 - A * (2 * f + 1)) % n
        C = (s0 - A * f * f - B * f) % n
        if all((A * (f + t) ** 2 + B * (f + t) + C) % n == s for t, s in enumerate(shifts)):
            found.append(QuadraticKey(A, B, C))
    return found


def attack_phrase(shifts: list[int], n: int) -> tuple[list[int], bool]:
    """Найменший період зсувів. Повертає (зсуви гасла, чи надійно)."""
    m = len(shifts)
    if m == 0:
        raise AttackError("Немає літер для аналізу")
    for L in range(1, m + 1):
        if all(shifts[t] == shifts[t + L] for t in range(m - L)):
            return shifts[:L], 2 * L <= m
    return shifts, False  # недосяжно, але для повноти


# ---------- повна атака ----------

def attack(alphabet, plain, cipher, first_position: int = 0) -> list[AttackResult]:
    """Пробує всі три моделі і повертає всі, що узгоджуються з парою текстів."""
    shifts = extract_shifts(alphabet, plain, cipher)
    n = alphabet.n
    m = len(shifts)
    if m == 0:
        raise AttackError("У відкритому тексті немає жодної літери алфавіту")
    if all(s == 0 for s in shifts):
        raise AttackError("Усі зсуви нульові: шифртекст збігається з відкритим текстом")

    results: list[AttackResult] = []

    if m >= 2:
        for k in attack_linear(shifts, n, first_position):
            results.append(AttackResult(
                "linear", k, reliable=m >= 2,
                note=f"A і B визначені за модулем n = {n}; знайдений ключ узгоджується з усіма {m} літерами",
            ))

    if m >= 3:
        lin = {(r.key.A % n) for r in results if r.kind == "linear"}
        cands = [k for k in attack_quadratic(shifts, n, first_position) if not (lin and k.A % n == 0)]
        for k in cands:
            note = f"коефіцієнти за модулем n = {n}"
            if len(cands) > 1:
                note += f"; кандидатів {len(cands)} (при парному n різні трійки можуть шифрувати однаково)"
            results.append(AttackResult("quadratic", k, reliable=m >= 4, note=note))

    period, reliable = attack_phrase(shifts, n)
    try:
        phrase = alphabet.phrase_from_indices(period)
        key: Key | None = PhraseKey(phrase)
        note = f"довжина гасла (мінімальний період) L = {len(period)}"
        if not reliable:
            note += "; текст коротший за два періоди — гасло відновлено лише в межах тексту, можливо, воно довше"
        results.append(AttackResult("phrase", key, reliable, note))
    except (ValueError, UnicodeDecodeError):
        results.append(AttackResult("phrase", None, reliable, f"зсуви гасла: {period}"))

    return results


def verify_key(alphabet, key: Key, plain, cipher, first_position: int = 0) -> bool:
    """Перевірка знайденого ключа: чи шифрує він `plain` у `cipher`."""
    from .cipher import TrithemiusCipher
    c = TrithemiusCipher(alphabet, key, first_position)
    if isinstance(alphabet, ByteAlphabet):
        return c.encrypt_bytes(plain) == cipher
    return c.encrypt_text(plain) == cipher
