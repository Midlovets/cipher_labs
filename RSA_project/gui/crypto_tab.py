# -*- coding: utf-8 -*-
"""
gui.crypto_tab
==============
Основна вкладка: сторона A шифрує повідомлення відкритим ключем сторони B,
сторона B розшифровує його своїм закритим ключем. Відповідає пунктам
3б і 3в завдання лабораторної роботи.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from rsa_lib import RSACryptoServiceProvider
from .theme import PALETTE
from .widgets import card, MonoText
from .key_dialog import KeyDialog


class CryptoTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=14)
        self.app = app  # посилання на головний додаток (спільний стан ключа)

        self._build()
        self.refresh_key_status()

    # ------------------------------------------------------------------
    def _build(self):
        # ---- Панель поточного ключа ----
        key_bar = card(self, "🔐 Поточна пара ключів (сторона B)")
        key_bar.pack(fill="x", pady=(0, 12))

        self.status_lbl = ttk.Label(key_bar, text="", style="Danger.TLabel")
        self.status_lbl.pack(side="left")

        btns = ttk.Frame(key_bar, style="Surface.TFrame")
        btns.pack(side="right")
        ttk.Button(btns, text="🔑 Сформувати відкритий ключ...",
                   style="Accent.TButton", command=self.open_key_dialog).pack(side="left", padx=4)
        ttk.Button(btns, text="📂 Імпортувати ключ (XML)",
                   command=self.import_key).pack(side="left", padx=4)

        # ---- Дві колонки: сторона A (шифрування) і сторона B (розшифрування) ----
        columns = ttk.Frame(self)
        columns.pack(fill="both", expand=True)
        columns.columnconfigure(0, weight=1)
        columns.columnconfigure(1, weight=1)
        columns.rowconfigure(0, weight=1)

        # --- Сторона A ---
        side_a = card(columns, "✉️  Сторона A — шифрування відкритим ключем")
        side_a.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        ttk.Label(side_a, text="Повідомлення:", style="Surface.TLabel").pack(anchor="w")
        self.msg_in = tk.Text(side_a, height=6, wrap="word", relief="solid",
                               borderwidth=1, padx=6, pady=6)
        self.msg_in.pack(fill="both", expand=True, pady=(2, 8))
        self.msg_in.insert("1.0", "Data to encrypt")

        ttk.Button(side_a, text="🔒 Зашифрувати  ➜", style="Accent.TButton",
                   command=self.do_encrypt).pack(anchor="e")

        ttk.Label(side_a, text="Шифротекст (hex):", style="Surface.TLabel")\
            .pack(anchor="w", pady=(10, 0))
        self.cipher_box = MonoText(side_a, height=6, copy_label="Копіювати шифротекст")
        self.cipher_box.pack(fill="both", expand=True, pady=(2, 0))

        # --- Сторона B ---
        side_b = card(columns, "🗝️  Сторона B — розшифрування закритим ключем")
        side_b.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        ttk.Label(side_b, text="Отриманий шифротекст (hex):", style="Surface.TLabel")\
            .pack(anchor="w")
        self.cipher_in = tk.Text(side_b, height=6, wrap="word", relief="solid",
                                  borderwidth=1, padx=6, pady=6)
        self.cipher_in.pack(fill="both", expand=True, pady=(2, 8))

        row = ttk.Frame(side_b, style="Surface.TFrame")
        row.pack(fill="x")
        ttk.Button(row, text="⬅ Взяти шифротекст зліва",
                   command=self.pull_ciphertext).pack(side="left")
        ttk.Button(row, text="🔓 Розшифрувати", style="Accent.TButton",
                   command=self.do_decrypt).pack(side="right")

        ttk.Label(side_b, text="Розшифроване повідомлення:", style="Surface.TLabel")\
            .pack(anchor="w", pady=(10, 0))
        self.plain_box = MonoText(side_b, height=6, copy_label="Копіювати результат")
        self.plain_box.pack(fill="both", expand=True, pady=(2, 0))

    # ------------------------------------------------------------------
    def open_key_dialog(self):
        KeyDialog(self.winfo_toplevel(), on_generated=self.app.set_provider)

    def import_key(self):
        path = filedialog.askopenfilename(
            filetypes=[("XML-файл ключа", "*.xml"), ("Усі файли", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                xml = f.read()
            provider = RSACryptoServiceProvider()
            provider.from_xml_string(xml)
            self.app.set_provider(provider)
            messagebox.showinfo("Імпортовано", "Ключ успішно завантажено з файлу.")
        except Exception as exc:
            messagebox.showerror("Помилка імпорту", str(exc))

    def refresh_key_status(self):
        provider = self.app.provider
        if provider.N is None:
            self.status_lbl.configure(text="Ключі ще не сформовано", style="Danger.TLabel")
        else:
            kind = "відкритий + закритий" if provider.has_private else "лише відкритий"
            self.status_lbl.configure(
                text=f"Активний ключ: N = {provider.N.bit_length()} біт, e = {provider.e}  "
                     f"({kind})",
                style="Success.TLabel")

    # ------------------------------------------------------------------
    def do_encrypt(self):
        provider = self.app.provider
        if not provider.has_public:
            messagebox.showwarning("Увага", "Спочатку сформуйте або імпортуйте ключ.")
            return
        text = self.msg_in.get("1.0", "end").rstrip("\n")
        if not text:
            messagebox.showwarning("Увага", "Введіть повідомлення для шифрування.")
            return
        try:
            pub_only = provider.public_only_copy()
            cipher = pub_only.encrypt(text.encode("utf-8"))
            self.cipher_box.set(cipher.hex())
        except Exception as exc:
            messagebox.showerror("Помилка шифрування", str(exc))

    def pull_ciphertext(self):
        self.cipher_in.delete("1.0", "end")
        self.cipher_in.insert("1.0", self.cipher_box.get())

    def do_decrypt(self):
        provider = self.app.provider
        if not provider.has_private:
            messagebox.showwarning("Увага", "Немає закритого ключа для розшифрування.")
            return
        hex_str = self.cipher_in.get("1.0", "end").strip()
        if not hex_str:
            messagebox.showwarning("Увага", "Вставте шифротекст (hex) для розшифрування.")
            return
        try:
            cipher = bytes.fromhex(hex_str)
            plain = provider.decrypt(cipher)
            self.plain_box.set(plain.decode("utf-8", errors="replace"))
        except Exception as exc:
            messagebox.showerror("Помилка розшифрування", str(exc))
