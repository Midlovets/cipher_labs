# -*- coding: utf-8 -*-
"""
gui.key_dialog
==============
Окремий діалог "Формування відкритого ключа" — саме цього вимагає
завдання лабораторної роботи ("передбачивши окремий діалог для
формування відкритого ключа"). Діалог:
  - дозволяє обрати розрядність ключа;
  - у фоновому потоці генерує пару (P, Q, N, e, d), не заморожуючи вікно;
  - показує результат (P, Q, N, e, d) та готовий XML відкритого ключа;
  - дозволяє скопіювати ключ або зберегти його у файл.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from rsa_lib import RSACryptoServiceProvider
from .theme import PALETTE, FONT_MONO
from .widgets import MonoText, run_in_thread


class KeyDialog(tk.Toplevel):
    KEY_SIZES = ["32", "64", "128", "256", "512", "768", "1024"]

    def __init__(self, parent, on_generated):
        super().__init__(parent)
        self.on_generated = on_generated
        self._provider = None

        self.title("Формування відкритого ключа")
        self.geometry("620x560")
        self.minsize(560, 480)
        self.configure(bg=PALETTE["bg"])
        self.transient(parent)
        self.grab_set()

        self._build()

    # ------------------------------------------------------------------
    def _build(self):
        pad = {"padx": 14, "pady": 8}

        header = ttk.Label(self, text="🔑  Формування пари ключів RSA", style="Header.TLabel")
        header.pack(anchor="w", **pad)

        sub = ttk.Label(
            self,
            style="SubHeader.TLabel",
            wraplength=560, justify="left",
            text=("Генеруються два простих числа P і Q, обчислюється модуль N = P·Q, "
                  "функція Ейлера f(N)=(P-1)(Q-1), відкрита експонента e та закрита "
                  "експонента d = e⁻¹ mod f(N)."),
        )
        sub.pack(anchor="w", padx=14)

        row = ttk.Frame(self)
        row.pack(fill="x", **pad)
        ttk.Label(row, text="Розрядність модуля N (біт):").pack(side="left")
        self.size_var = tk.StringVar(value="512")
        box = ttk.Combobox(row, textvariable=self.size_var, state="readonly",
                            values=self.KEY_SIZES, width=8)
        box.pack(side="left", padx=8)

        self.gen_btn = ttk.Button(row, text="⚙ Згенерувати пару ключів",
                                   style="Accent.TButton", command=self._generate)
        self.gen_btn.pack(side="left", padx=12)

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=14)

        self.status_lbl = ttk.Label(self, text="Очікування запуску генерації…",
                                     style="Status.TLabel")
        self.status_lbl.pack(anchor="w", padx=14, pady=(4, 10))

        details_card = ttk.LabelFrame(self, text="Параметри ключа", padding=10)
        details_card.pack(fill="x", padx=14)
        self.details = tk.Text(details_card, height=6, font=(FONT_MONO, 9),
                                relief="flat", bg=PALETTE["surface"])
        self.details.pack(fill="x")
        self.details.configure(state="disabled")

        ttk.Label(self, text="Відкритий ключ (XML, ToXmlString(false)) — передається стороні A:",
                   style="SubHeader.TLabel").pack(anchor="w", padx=14, pady=(12, 2))
        self.pub_box = MonoText(self, height=7, copy_label="Копіювати відкритий ключ")
        self.pub_box.pack(fill="both", expand=True, padx=14)

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=14, pady=12)
        ttk.Button(btns, text="💾 Зберегти відкритий ключ у файл",
                   command=self._save_public).pack(side="left")
        ttk.Button(btns, text="Закрити", command=self.destroy).pack(side="right")

    # ------------------------------------------------------------------
    def _set_details(self, provider: RSACryptoServiceProvider):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        lines = [
            f"P = {provider.P}",
            f"Q = {provider.Q}",
            f"N = P·Q = {provider.N}   ({provider.N.bit_length()} біт)",
            f"e (відкрита експонента) = {provider.e}",
            f"d (закрита експонента)  = {provider.d}",
        ]
        self.details.insert("1.0", "\n".join(lines))
        self.details.configure(state="disabled")

    def _generate(self):
        try:
            bits = int(self.size_var.get())
        except ValueError:
            bits = 512

        self.gen_btn.configure(state="disabled")
        self.progress.start(12)
        self.status_lbl.configure(text="Генерація простих чисел… це може зайняти кілька секунд")

        def progress_cb(msg):
            self.after(0, lambda: self.status_lbl.configure(text=msg))

        def work():
            provider = RSACryptoServiceProvider()
            provider.generate_keypair(bits, progress_cb=progress_cb)
            return provider

        def done(provider):
            self.progress.stop()
            self.gen_btn.configure(state="normal")
            self._provider = provider
            self._set_details(provider)
            self.pub_box.set(provider.to_xml_string(include_private=False))
            self.status_lbl.configure(
                text=f"Готово. N має {provider.N.bit_length()} біт.")
            if self.on_generated:
                self.on_generated(provider)

        def error(exc):
            self.progress.stop()
            self.gen_btn.configure(state="normal")
            self.status_lbl.configure(text="Помилка генерації ключа")
            messagebox.showerror("Помилка", str(exc), parent=self)

        run_in_thread(self, work, on_done=done, on_error=error)

    def _save_public(self):
        if self._provider is None:
            messagebox.showwarning("Увага", "Спочатку згенеруйте ключ.", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".xml",
            filetypes=[("XML-файл ключа", "*.xml"), ("Усі файли", "*.*")],
            initialfile="public_key.xml")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(self._provider.to_xml_string(include_private=False))
        messagebox.showinfo("Збережено", f"Відкритий ключ збережено у файл:\n{path}", parent=self)
