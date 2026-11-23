# -*- coding: utf-8 -*-
"""
rsa_lib.core
============
Математичний апарат RSA та клас RSACryptoServiceProvider — аналог
однойменного класу з простору імен System.Security.Cryptography (.NET),
про який йдеться у методичці до лаб. роботи №7.

Теорія (коротко, з методички):
  N = P*Q,  P, Q — великі прості числа;
  f(N) = (P-1)(Q-1);
  e — відкрита експонента, взаємно проста з f(N);
  d = e^-1 mod f(N) — закрита експонента;
  Шифрування:    c = m^e mod N      (відкритий ключ (N, e))
  Розшифрування: m = c^d mod N      (закритий ключ (N, d))

  Задача факторизації N (знаходження P, Q за відомим N) є складною,
  якщо P, Q — великі; саме на цьому ґрунтується стійкість RSA.
"""

import random
import re
from math import gcd

_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


# ----------------------------------------------------------------------
#  1. Задача перевірки числа на простоту (порівняно проста задача)
# ----------------------------------------------------------------------
def is_prime(n: int, rounds: int = 20) -> bool:
    """Ймовірнісний тест простоти Міллера-Рабіна."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Генерація випадкового простого числа заданої розрядності."""
    bits = max(bits, 8)
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(n):
            return n


def egcd(a: int, b: int):
    """Розширений алгоритм Евкліда: повертає (gcd, x, y): a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x


def modinv(a: int, m: int) -> int:
    """Обернений елемент a^-1 mod m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Оберненого елемента не існує (НСД != 1)")
    return x % m


class RSAError(Exception):
    pass


# ----------------------------------------------------------------------
#  2. Клас-аналог RSACryptoServiceProvider
# ----------------------------------------------------------------------
class RSACryptoServiceProvider:
    """
    Аналог .NET класу RSACryptoServiceProvider.

    Публічний ключ : (Modulus=N, Exponent=e)        -> можна передавати відкрито
    Закритий ключ  : (Modulus=N, D=d, P, Q)          -> зберігається лише у власника

    Методи відповідають методичці:
      generate_keypair()         — генерація пари ключів
      to_xml_string(include_private)   — аналог ToXmlString
      from_xml_string(xml)             — аналог FromXmlString
      encrypt(data) / decrypt(data)    — аналог Encrypt/Decrypt
    """

    def __init__(self, key_size: int = 512):
        self.key_size = key_size
        self.N = None
        self.e = None
        self.d = None
        self.P = None
        self.Q = None

    # ---------------- Генерація пари ключів ----------------
    def generate_keypair(self, key_size: int = None, progress_cb=None):
        """
        progress_cb(str) — необов'язковий колбек для відображення прогресу
        (наприклад, щоб інтерфейс показував "генерується P...", "генерується Q...").
        """
        if key_size:
            self.key_size = key_size
        bits = max(self.key_size // 2, 8)

        if progress_cb:
            progress_cb("Генерація простого числа P...")
        p = generate_prime(bits)

        if progress_cb:
            progress_cb("Генерація простого числа Q...")
        q = generate_prime(bits)
        while q == p:
            q = generate_prime(bits)

        if progress_cb:
            progress_cb("Обчислення N, f(N), e, d...")

        self.P, self.Q = p, q
        self.N = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        if gcd(e, phi) != 1:
            e = 3
            while gcd(e, phi) != 1:
                e += 2
        self.e = e
        self.d = modinv(e, phi)
        return self.N, self.e, self.d

    @property
    def has_public(self) -> bool:
        return self.N is not None and self.e is not None

    @property
    def has_private(self) -> bool:
        return self.N is not None and self.d is not None

    # ---------------- ToXmlString / FromXmlString ----------------
    def to_xml_string(self, include_private: bool = False) -> str:
        if self.N is None:
            raise RSAError("Ключі ще не згенеровано")
        if include_private:
            if self.d is None:
                raise RSAError("Закритий ключ відсутній")
            return (
                "<RSAKeyValue>\n"
                f"  <Modulus>{self.N}</Modulus>\n"
                f"  <Exponent>{self.e}</Exponent>\n"
                f"  <D>{self.d}</D>\n"
                f"  <P>{self.P}</P>\n"
                f"  <Q>{self.Q}</Q>\n"
                "</RSAKeyValue>"
            )
        return (
            "<RSAKeyValue>\n"
            f"  <Modulus>{self.N}</Modulus>\n"
            f"  <Exponent>{self.e}</Exponent>\n"
            "</RSAKeyValue>"
        )

    def from_xml_string(self, xml: str):
        def grab(tag):
            m = re.search(rf"<{tag}>\s*(\d+)\s*</{tag}>", xml)
            return int(m.group(1)) if m else None

        n = grab("Modulus")
        e = grab("Exponent")
        if n is None or e is None:
            raise RSAError("Некоректний формат XML-ключа")
        self.N, self.e = n, e
        d, p, q = grab("D"), grab("P"), grab("Q")
        self.d = d if d is not None else self.d
        self.P = p if p is not None else self.P
        self.Q = q if q is not None else self.Q
        self.key_size = self.N.bit_length()

    def public_only_copy(self) -> "RSACryptoServiceProvider":
        """Повертає новий провайдер, що містить ЛИШЕ відкритий ключ (імітація сторони A)."""
        other = RSACryptoServiceProvider()
        other.from_xml_string(self.to_xml_string(include_private=False))
        return other

    # ---------------- Encrypt / Decrypt ----------------
    def _n_bytes(self) -> int:
        return (self.N.bit_length() + 7) // 8

    def encrypt(self, data: bytes) -> bytes:
        """Шифрування відкритим ключем (N, e). Дані розбиваються на блоки."""
        if not self.has_public:
            raise RSAError("Відсутній відкритий ключ")
        n_bytes = self._n_bytes()
        plain_block = n_bytes - 2  # 1 байт довжини + запас на 1 байт, щоб m < N
        if plain_block < 1:
            raise RSAError("Розмір ключа замалий для шифрування (виберіть більшу розрядність)")

        out = bytearray()
        for i in range(0, len(data), plain_block):
            chunk = data[i:i + plain_block]
            header = bytes([len(chunk)])
            padded = header + chunk + bytes(plain_block - len(chunk))
            m = int.from_bytes(padded, "big")
            c = pow(m, self.e, self.N)
            out += c.to_bytes(n_bytes, "big")
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        """Розшифрування закритим ключем (N, d)."""
        if not self.has_private:
            raise RSAError("Відсутній закритий ключ")
        n_bytes = self._n_bytes()
        plain_block = n_bytes - 2
        if len(data) % n_bytes != 0:
            raise RSAError("Довжина шифротексту не кратна розміру блоку — пошкоджені дані")

        out = bytearray()
        for i in range(0, len(data), n_bytes):
            block = data[i:i + n_bytes]
            c = int.from_bytes(block, "big")
            m = pow(c, self.d, self.N)
            padded = m.to_bytes(plain_block + 1, "big")
            length = padded[0]
            out += padded[1:1 + length]
        return bytes(out)
