# -*- coding: utf-8 -*-
"""
gui.example_tab
================
Вкладка "Числовий приклад": п.1 і п.4 ходу виконання роботи —
відшукати числовий приклад RSA (класичний приклад p=61, q=53 з
Вікіпедії) і перевірити правильність роботи реалізованої системи
на цих даних.
"""

import tkinter as tk
from tkinter import ttk

from rsa_lib import modinv
from .theme import FONT_MONO
from .widgets import card


class ExampleTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=14)
        self.app = app
        self._build()

    def _build(self):
        header = ttk.Label(
            self, style="Header.TLabel",
            text="🧮 Числовий приклад RSA (класичний приклад з Вікіпедії)")
        header.pack(anchor="w")

        ttk.Label(
            self, style="SubHeader.TLabel", wraplength=820, justify="left",
            text=("Використано загальновідомий навчальний приклад: p = 61, q = 53, "
                  "e = 17, повідомлення m = 65. Нижче — покроковий розрахунок за "
                  "формулами з методички та перевірка, що m' = m."),
        ).pack(anchor="w", pady=(2, 10))

        box = card(self, "Покроковий розрахунок")
        box.pack(fill="both", expand=True)

        self.out = tk.Text(box, height=18, font=(FONT_MONO, 10), relief="flat")
        self.out.pack(fill="both", expand=True)
        self.out.tag_configure("ok", foreground="#1f8a5c", font=(FONT_MONO, 10, "bold"))
        self.out.tag_configure("title", foreground="#2f5fd6", font=(FONT_MONO, 10, "bold"))
        self.out.configure(state="disabled")

        ttk.Button(self, text="▶ Виконати приклад", style="Accent.TButton",
                   command=self.run_example).pack(pady=10)

        self.run_example()

    def run_example(self):
        p, q = 61, 53
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 17
        d = modinv(e, phi)
        m = 65

        c = pow(m, e, n)
        m_back = pow(c, d, n)

        self.out.configure(state="normal")
        self.out.delete("1.0", "end")

        def line(text, tag=None):
            self.out.insert("end", text + "\n", tag or ())

        line("1) Обрано два простих числа:", "title")
        line(f"   p = {p},  q = {q}\n")

        line("2) Модуль та функція Ейлера:", "title")
        line(f"   N = p*q = {n}")
        line(f"   f(N) = (p-1)*(q-1) = {phi}\n")

        line("3) Відкрита експонента e (взаємно проста з f(N)):", "title")
        line(f"   e = {e}   =>   gcd(e, f(N)) = {__import__('math').gcd(e, phi)}\n")

        line("4) Закрита експонента d = e^-1 mod f(N):", "title")
        line(f"   d = {d}")
        line(f"   Перевірка:  e*d mod f(N) = {(e * d) % phi}  (має дорівнювати 1)\n")

        line("5) Шифрування повідомлення m відкритим ключем (N, e):", "title")
        line(f"   m = {m}")
        line(f"   c = m^e mod N = {m}^{e} mod {n} = {c}\n")

        line("6) Розшифрування шифротексту c закритим ключем (N, d):", "title")
        line(f"   m' = c^d mod N = {c}^{d} mod {n} = {m_back}\n")

        line(f"РЕЗУЛЬТАТ ПЕРЕВІРКИ:  m' == m   ->   {m_back == m}",
             "ok" if m_back == m else None)

        self.out.configure(state="disabled")
