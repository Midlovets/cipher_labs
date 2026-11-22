# -*- coding: utf-8 -*-
"""
Комп'ютерний практикум №5 — «Шифр DES»
GUI-застосунок на tkinter для шифрування/розшифрування тексту та файлів.

Підтримує:
  - основне завдання: DES з усіма можливими режимами (ECB/CBC/CFB/OFB/CTR);
  - додаткове завдання 1: TripleDES та AES;
  - додаткове завдання 2: динамічний вибір одного з трьох шифрів (DES/TripleDES/AES).

Усі алгоритми реалізовані самостійно на чистому Python (без сторонніх
бібліотек) у файлах des.py / aes.py / modes.py — аналог криптопровайдерів
.NET (DESCryptoServiceProvider, TripleDESCryptoServiceProvider, AesCryptoServiceProvider).
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from crypto_provider import CryptoProvider, ALGORITHMS, block_size_of, normalize_key
import modes


class DesLabApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Комп'ютерний практикум №5 — Шифр DES / 3DES / AES")
        self.geometry("820x640")
        self.minsize(760, 560)

        self._build_widgets()
        self._on_algorithm_change()

    # ------------------------------------------------------------------ UI
    def _build_widgets(self):
        pad = {"padx": 8, "pady": 6}

        # ---- Блок налаштувань алгоритму ----
        settings = ttk.LabelFrame(self, text="Параметри шифрування")
        settings.pack(fill="x", **pad)

        ttk.Label(settings, text="Алгоритм:").grid(row=0, column=0, sticky="w", **pad)
        self.algo_var = tk.StringVar(value="DES")
        algo_combo = ttk.Combobox(settings, textvariable=self.algo_var,
                                   values=list(ALGORITHMS.keys()), state="readonly", width=12)
        algo_combo.grid(row=0, column=1, sticky="w", **pad)
        algo_combo.bind("<<ComboboxSelected>>", lambda e: self._on_algorithm_change())

        ttk.Label(settings, text="Режим:").grid(row=0, column=2, sticky="w", **pad)
        self.mode_var = tk.StringVar(value="CBC")
        self.mode_combo = ttk.Combobox(settings, textvariable=self.mode_var,
                                        values=modes.ALL_MODES, state="readonly", width=8)
        self.mode_combo.grid(row=0, column=3, sticky="w", **pad)
        self.mode_combo.bind("<<ComboboxSelected>>", lambda e: self._on_mode_change())

        ttk.Label(settings, text="Ключ:").grid(row=1, column=0, sticky="w", **pad)
        self.key_var = tk.StringVar(value="ABCDEFGH")
        self.key_entry = ttk.Entry(settings, textvariable=self.key_var, width=40)
        self.key_entry.grid(row=1, column=1, columnspan=2, sticky="we", **pad)
        ttk.Button(settings, text="Згенерувати", command=self._generate_key).grid(
            row=1, column=3, sticky="w", **pad)
        self.key_hint = ttk.Label(settings, text="", foreground="gray")
        self.key_hint.grid(row=2, column=1, columnspan=3, sticky="w", padx=8)

        self.iv_label = ttk.Label(settings, text="IV (вектор ініціалізації):")
        self.iv_label.grid(row=3, column=0, sticky="w", **pad)
        self.iv_var = tk.StringVar(value="ABCDEFGH")
        self.iv_entry = ttk.Entry(settings, textvariable=self.iv_var, width=40)
        self.iv_entry.grid(row=3, column=1, columnspan=2, sticky="we", **pad)
        self.iv_btn = ttk.Button(settings, text="Згенерувати", command=self._generate_iv)
        self.iv_btn.grid(row=3, column=3, sticky="w", **pad)

        settings.columnconfigure(1, weight=1)

        # ---- Блок тексту ----
        text_frame = ttk.LabelFrame(self, text="Текст (для швидкого тесту — без роботи з файлом)")
        text_frame.pack(fill="both", expand=True, **pad)

        ttk.Label(text_frame, text="Відкритий текст:").pack(anchor="w", padx=8)
        self.plain_text = tk.Text(text_frame, height=5, wrap="word")
        self.plain_text.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self.plain_text.insert("1.0", "Hello world! Привіт, світ!")

        btns = ttk.Frame(text_frame)
        btns.pack(fill="x", padx=8, pady=4)
        ttk.Button(btns, text="Зашифрувати ▼", command=self._encrypt_text).pack(side="left", padx=4)
        ttk.Button(btns, text="Розшифрувати ▲", command=self._decrypt_text).pack(side="left", padx=4)
        ttk.Button(btns, text="Очистити", command=self._clear_text).pack(side="left", padx=4)

        ttk.Label(text_frame, text="Шифротекст (hex):").pack(anchor="w", padx=8)
        self.cipher_text = tk.Text(text_frame, height=5, wrap="word")
        self.cipher_text.pack(fill="both", expand=True, padx=8, pady=(0, 6))

        # ---- Блок роботи з файлами ----
        file_frame = ttk.LabelFrame(self, text="Робота з файлом")
        file_frame.pack(fill="x", **pad)

        self.in_file_var = tk.StringVar()
        ttk.Label(file_frame, text="Вхідний файл:").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(file_frame, textvariable=self.in_file_var, width=55).grid(
            row=0, column=1, sticky="we", **pad)
        ttk.Button(file_frame, text="Огляд...", command=self._browse_in_file).grid(
            row=0, column=2, sticky="w", **pad)

        self.out_file_var = tk.StringVar()
        ttk.Label(file_frame, text="Вихідний файл:").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(file_frame, textvariable=self.out_file_var, width=55).grid(
            row=1, column=1, sticky="we", **pad)
        ttk.Button(file_frame, text="Огляд...", command=self._browse_out_file).grid(
            row=1, column=2, sticky="w", **pad)

        file_btns = ttk.Frame(file_frame)
        file_btns.grid(row=2, column=0, columnspan=3, pady=6)
        ttk.Button(file_btns, text="Зашифрувати файл", command=self._encrypt_file).pack(
            side="left", padx=6)
        ttk.Button(file_btns, text="Розшифрувати файл", command=self._decrypt_file).pack(
            side="left", padx=6)

        file_frame.columnconfigure(1, weight=1)

        # ---- Статус-рядок ----
        self.status_var = tk.StringVar(value="Готово.")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.pack(fill="x", side="bottom")

    # ---------------------------------------------------------- допоміжне
    def _on_algorithm_change(self):
        algo = self.algo_var.get()
        bs = block_size_of(algo)
        sizes = ALGORITHMS[algo]["key_sizes"]
        self.key_hint.config(
            text=f"Довжина ключа для {algo}: {'/'.join(str(s) for s in sizes)} байт "
                 f"(довільний текст буде обрізано/доповнено нулями); розмір блоку: {bs} байт")
        self._on_mode_change()

    def _on_mode_change(self):
        algo = self.algo_var.get()
        mode = self.mode_var.get()
        needs_iv = mode in modes.MODES_REQUIRING_IV
        state = "normal" if needs_iv else "disabled"
        self.iv_entry.config(state=state)
        self.iv_btn.config(state=state)
        if needs_iv:
            self.iv_label.config(text=f"IV (вектор ініціалізації, {block_size_of(algo)} байт):")
        else:
            self.iv_label.config(text="IV (не потрібен для режиму ECB):")

    def _generate_key(self):
        algo = self.algo_var.get()
        size = ALGORITHMS[algo]["key_sizes"][0]
        self.key_var.set(os.urandom(size).hex())

    def _generate_iv(self):
        algo = self.algo_var.get()
        self.iv_var.set(os.urandom(block_size_of(algo)).hex())

    def _get_key_bytes(self) -> bytes:
        raw = self.key_var.get()
        # якщо введено валідний hex потрібної довжини*2 — трактуємо як hex,
        # інакше — як звичайний текст (ASCII/UTF-8), як у лістингу роботи.
        algo = self.algo_var.get()
        try:
            if all(c in "0123456789abcdefABCDEF" for c in raw) and len(raw) % 2 == 0 and len(raw) >= 16:
                key = bytes.fromhex(raw)
            else:
                key = raw.encode("utf-8")
        except ValueError:
            key = raw.encode("utf-8")
        return normalize_key(algo, key)

    def _get_iv_bytes(self):
        algo = self.algo_var.get()
        mode = self.mode_var.get()
        if mode not in modes.MODES_REQUIRING_IV:
            return None
        raw = self.iv_var.get()
        bs = block_size_of(algo)
        try:
            if all(c in "0123456789abcdefABCDEF" for c in raw) and len(raw) == bs * 2:
                return bytes.fromhex(raw)
        except ValueError:
            pass
        data = raw.encode("utf-8")
        return (data[:bs]).ljust(bs, b"\x00")

    def _make_provider(self) -> CryptoProvider:
        algo = self.algo_var.get()
        mode = self.mode_var.get()
        key = self._get_key_bytes()
        iv = self._get_iv_bytes()
        return CryptoProvider(algo, mode, key, iv)

    def _set_status(self, text):
        self.status_var.set(text)

    # ------------------------------------------------------- дії: текст
    def _encrypt_text(self):
        try:
            provider = self._make_provider()
            data = self.plain_text.get("1.0", "end-1c").encode("utf-8")
            ct = provider.encrypt_bytes(data)
            self.cipher_text.delete("1.0", "end")
            self.cipher_text.insert("1.0", ct.hex())
            self._set_status(f"Текст зашифровано ({self.algo_var.get()}/{self.mode_var.get()}), "
                              f"{len(ct)} байт шифротексту.")
        except Exception as exc:
            messagebox.showerror("Помилка шифрування", str(exc))

    def _decrypt_text(self):
        try:
            provider = self._make_provider()
            hex_str = self.cipher_text.get("1.0", "end-1c").strip()
            ct = bytes.fromhex(hex_str)
            pt = provider.decrypt_bytes(ct)
            self.plain_text.delete("1.0", "end")
            self.plain_text.insert("1.0", pt.decode("utf-8", errors="replace"))
            self._set_status("Текст успішно розшифровано.")
        except Exception as exc:
            messagebox.showerror("Помилка розшифрування",
                                  f"{exc}\n\nПеревірте правильність ключа, IV та режиму.")

    def _clear_text(self):
        self.plain_text.delete("1.0", "end")
        self.cipher_text.delete("1.0", "end")

    # ------------------------------------------------------- дії: файли
    def _browse_in_file(self):
        path = filedialog.askopenfilename(title="Оберіть вхідний файл")
        if path:
            self.in_file_var.set(path)
            if not self.out_file_var.get():
                self.out_file_var.set(path + ".enc")

    def _browse_out_file(self):
        path = filedialog.asksaveasfilename(title="Оберіть вихідний файл")
        if path:
            self.out_file_var.set(path)

    def _encrypt_file(self):
        in_path, out_path = self.in_file_var.get(), self.out_file_var.get()
        if not in_path or not out_path:
            messagebox.showwarning("Увага", "Оберіть вхідний і вихідний файли.")
            return
        try:
            provider = self._make_provider()
            provider.encrypt_file(in_path, out_path)
            size = os.path.getsize(out_path)
            self._set_status(f"Файл зашифровано -> {out_path} ({size} байт).")
            messagebox.showinfo("Готово", f"Файл успішно зашифровано:\n{out_path}")
        except Exception as exc:
            messagebox.showerror("Помилка шифрування файлу", str(exc))

    def _decrypt_file(self):
        in_path, out_path = self.in_file_var.get(), self.out_file_var.get()
        if not in_path or not out_path:
            messagebox.showwarning("Увага", "Оберіть вхідний і вихідний файли.")
            return
        try:
            provider = self._make_provider()
            provider.decrypt_file(in_path, out_path)
            size = os.path.getsize(out_path)
            self._set_status(f"Файл розшифровано -> {out_path} ({size} байт).")
            messagebox.showinfo("Готово", f"Файл успішно розшифровано:\n{out_path}")
        except Exception as exc:
            messagebox.showerror("Помилка розшифрування файлу",
                                  f"{exc}\n\nПеревірте правильність ключа, IV та режиму.")


if __name__ == "__main__":
    app = DesLabApp()
    app.mainloop()
