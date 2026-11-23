# -*- coding: utf-8 -*-
"""
rsa_lib.attack
==============
Додаткове завдання лабораторної роботи:
  1. Ознайомитись з можливостями розкладання числа на прості множники
     і скористатись цим для атаки на шифр RSA.
  2. Визначити область значень параметрів RSA, за яких така атака є реальною.

Реалізовано атаку методом перебору дільників (аналог простого онлайн-
калькулятора факторизації) та функцію explore_feasibility, яка на практиці
(шляхом експерименту) визначає, за якої розрядності N атака ще встигає
спрацювати за прийнятний час, а за якої — вже ні.
"""

import time
from .core import RSACryptoServiceProvider


def trial_division_attack(n: int, time_limit: float = 5.0):
    """
    Атака на RSA шляхом розкладання N = P*Q методом перебору дільників.
    Повертає (p, q, elapsed_seconds, success).
    """
    start = time.time()
    if n % 2 == 0:
        return 2, n // 2, time.time() - start, True
    i = 3
    checkpoint = 0
    while i * i <= n:
        if n % i == 0:
            return i, n // i, time.time() - start, True
        i += 2
        checkpoint += 1
        if checkpoint >= 200_000:
            checkpoint = 0
            if time.time() - start > time_limit:
                return None, None, time.time() - start, False
    return None, None, time.time() - start, False


def explore_feasibility(bit_sizes, time_limit=8.0, on_step=None, stop_flag=None):
    """
    Експериментально визначає залежність часу атаки від розрядності ключа N.

    Для кожного значення з bit_sizes:
      - генерується нова пара ключів RSA відповідної розрядності;
      - виконується атака перебором дільників з обмеженням time_limit;
      - результат передається у колбек on_step(dict), якщо він заданий.

    stop_flag — об'єкт з атрибутом .is_set() (напр. threading.Event) для
    дострокової зупинки довгого дослідження.

    Повертає список результатів:
      [{"bits": int, "elapsed": float, "success": bool}, ...]
    """
    results = []
    for bits in bit_sizes:
        if stop_flag is not None and stop_flag.is_set():
            break
        prov = RSACryptoServiceProvider()
        prov.generate_keypair(bits)
        p, q, elapsed, ok = trial_division_attack(prov.N, time_limit=time_limit)
        row = {
            "bits": prov.N.bit_length(),
            "elapsed": elapsed,
            "success": ok,
            "p": p,
            "q": q,
        }
        results.append(row)
        if on_step:
            on_step(row)
        if not ok:
            # час вичерпано на такій розрядності — більші розрядності
            # не мають сенсу перевіряти (атака лише ще довша)
            break
    return results
