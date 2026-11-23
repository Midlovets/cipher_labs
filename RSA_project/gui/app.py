# -*- coding: utf-8 -*-
"""
gui.app
=======
Головне вікно лабораторної роботи: об'єднує вкладки
"Шифрування/Розшифрування", "Числовий приклад" та "Атака факторизації"
навколо спільного стану — поточної пари ключів RSA.
"""

import tkinter as tk
from tkinter import ttk

from rsa_lib import RSACryptoServiceProvider
from .theme import apply_theme, PALETTE
from .crypto_tab import CryptoTab
from .example_tab import ExampleTab
from .attack_tab import AttackTab


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Лабораторна робота №7 — Шифрування з відкритим ключем (RSA)")
        self.geometry("1000x720")
        self.minsize(900, 640)

        apply_theme(self)

        # Спільний стан: поточна пара ключів сторони B
        self.provider = RSACryptoServiceProvider()

        self._build_header()
        self._build_notebook()
        self._build_statusbar()

    # ------------------------------------------------------------------
    def _build_header(self):
        header = ttk.Frame(self, padding=(18, 14, 18, 6))
        header.pack(fill="x")
        ttk.Label(header, text="Шифрування з відкритим ключем на основі алгоритму RSA",
                   style="Header.TLabel").pack(anchor="w")
        ttk.Label(header,
                   text="Комп'ютерний практикум №7  •  криптопровайдер RSACryptoServiceProvider",
                   style="SubHeader.TLabel").pack(anchor="w")

    def _build_notebook(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=18, pady=(6, 0))

        self.crypto_tab = CryptoTab(nb, self)
        self.example_tab = ExampleTab(nb, self)
        self.attack_tab = AttackTab(nb, self)

        nb.add(self.crypto_tab, text="  🔒 Шифрування / Розшифрування  ")
        nb.add(self.example_tab, text="  🧮 Числовий приклад  ")
        nb.add(self.attack_tab, text="  ⚔️ Атака факторизації  ")

    def _build_statusbar(self):
        bar = ttk.Frame(self, padding=(18, 6))
        bar.pack(fill="x", side="bottom")
        ttk.Label(bar, text="Лаб. №7 • RSA • Python + Tkinter", style="Status.TLabel")\
            .pack(side="left")

    # ------------------------------------------------------------------
    def set_provider(self, provider: RSACryptoServiceProvider):
        """Викликається діалогом генерації / імпорту ключа."""
        self.provider = provider
        self.crypto_tab.refresh_key_status()
