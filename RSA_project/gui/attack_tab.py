# -*- coding: utf-8 -*-
"""
gui.attack_tab
==============
Додаткове завдання:
  1. Атака на N шляхом розкладання на прості множники (перебір дільників —
     аналог онлайн-калькулятора факторизації).
  2. Експериментальне визначення області значень розрядності N, за яких
     така атака є реальною (вкладка "Дослідження" з таблицею результатів).
"""

import threading
import tkinter as tk
from tkinter import ttk, messagebox

from rsa_lib import trial_division_attack, explore_feasibility
from .widgets import card


class AttackTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=14)
        self.app = app
        self._stop_flag = threading.Event()
        self._build()

    # ------------------------------------------------------------------
    def _build(self):
        header = ttk.Label(self, style="Header.TLabel",
                            text="⚔️  Атака факторизації на RSA")
        header.pack(anchor="w")
        ttk.Label(
            self, style="SubHeader.TLabel", wraplength=860, justify="left",
            text=("Атака полягає у розкладанні модуля N = P·Q на множники методом "
                  "перебору дільників (найпростіший аналог онлайн-калькулятора "
                  "факторизації). Якщо P і Q вдається знайти — закритий ключ "
                  "обчислюється так само, як і легітимним власником."),
        ).pack(anchor="w", pady=(2, 10))

        # ---- Разова атака ----
        single = card(self, "Разова атака на конкретне N")
        single.pack(fill="x", pady=(0, 12))

        row = ttk.Frame(single, style="Surface.TFrame")
        row.pack(fill="x")
        ttk.Label(row, text="N =", style="Surface.TLabel").pack(side="left")
        self.n_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.n_var, width=60).pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(row, text="Взяти N з поточного ключа",
                   command=self._fill_from_key).pack(side="left", padx=4)

        row2 = ttk.Frame(single, style="Surface.TFrame")
        row2.pack(fill="x", pady=(8, 0))
        ttk.Label(row2, text="Ліміт часу (с):", style="Surface.TLabel").pack(side="left")
        self.limit_var = tk.StringVar(value="5")
        ttk.Combobox(row2, textvariable=self.limit_var, state="readonly",
                     values=["2", "5", "10", "20", "60"], width=5).pack(side="left", padx=6)
        ttk.Button(row2, text="🧨 Спробувати факторизувати", style="Accent.TButton",
                   command=self._run_single).pack(side="left", padx=10)

        self.single_result = ttk.Label(single, text="", style="SubHeader.TLabel",
                                        wraplength=860, justify="left")
        self.single_result.pack(anchor="w", pady=(8, 0))

        # ---- Дослідження області реальності атаки ----
        explore = card(self, "Дослідження: за яких розрядностей N атака ще реальна")
        explore.pack(fill="both", expand=True)

        row3 = ttk.Frame(explore, style="Surface.TFrame")
        row3.pack(fill="x")
        ttk.Label(row3, text="Розрядності N для перевірки (біт, через кому):",
                   style="Surface.TLabel").pack(side="left")
        self.sizes_var = tk.StringVar(value="16,20,24,28,32,36,40,44,48")
        ttk.Entry(row3, textvariable=self.sizes_var, width=40).pack(side="left", padx=6)
        ttk.Label(row3, text="Ліміт на кожну спробу (с):",
                   style="Surface.TLabel").pack(side="left", padx=(12, 0))
        self.explore_limit_var = tk.StringVar(value="8")
        ttk.Combobox(row3, textvariable=self.explore_limit_var, state="readonly",
                     values=["3", "5", "8", "15"], width=5).pack(side="left", padx=6)

        self.explore_btn = ttk.Button(row3, text="▶ Запустити дослідження",
                                       style="Accent.TButton", command=self._run_explore)
        self.explore_btn.pack(side="left", padx=10)
        self.stop_btn = ttk.Button(row3, text="⏹ Зупинити", command=self._stop_explore,
                                    state="disabled")
        self.stop_btn.pack(side="left")

        self.progress = ttk.Progressbar(explore, mode="indeterminate")
        self.progress.pack(fill="x", pady=(8, 8))

        columns = ("bits", "time", "result")
        self.tree = ttk.Treeview(explore, columns=columns, show="headings", height=8)
        self.tree.heading("bits", text="Розрядність N (біт)")
        self.tree.heading("time", text="Час атаки (с)")
        self.tree.heading("result", text="Результат")
        self.tree.column("bits", width=160, anchor="center")
        self.tree.column("time", width=140, anchor="center")
        self.tree.column("result", width=260, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.tag_configure("ok", foreground="#1f8a5c")
        self.tree.tag_configure("fail", foreground="#c0392b")

        self.conclusion = ttk.Label(explore, text="", style="SubHeader.TLabel",
                                     wraplength=860, justify="left")
        self.conclusion.pack(anchor="w", pady=(8, 0))

    # ------------------------------------------------------------------
    def _fill_from_key(self):
        provider = self.app.provider
        if provider.N is None:
            messagebox.showwarning("Увага", "Ключі ще не сформовано.")
            return
        self.n_var.set(str(provider.N))

    def _run_single(self):
        raw = self.n_var.get().strip()
        if not raw.isdigit():
            messagebox.showwarning("Увага", "Введіть N — додатне ціле число.")
            return
        n = int(raw)
        try:
            limit = float(self.limit_var.get())
        except ValueError:
            limit = 5.0

        self.single_result.configure(text=f"Виконується перебір дільників N "
                                           f"({n.bit_length()} біт)...")
        self.update_idletasks()

        p, q, elapsed, ok = trial_division_attack(n, time_limit=limit)
        if ok:
            self.single_result.configure(
                text=(f"✅ Успіх за {elapsed:.3f} с: P = {p}, Q = {q}  "
                      f"(перевірка P*Q {'=' if p*q==n else '≠'} N)"),
                style="Success.TLabel")
        else:
            self.single_result.configure(
                text=(f"❌ За {elapsed:.3f} с дільник не знайдено — для N розрядністю "
                      f"{n.bit_length()} біт атака перебором нереальна за цей час."),
                style="Danger.TLabel")

    # ------------------------------------------------------------------
    def _run_explore(self):
        try:
            sizes = [int(s.strip()) for s in self.sizes_var.get().split(",") if s.strip()]
        except ValueError:
            messagebox.showwarning("Увага", "Некоректний список розрядностей.")
            return
        if not sizes:
            return
        try:
            limit = float(self.explore_limit_var.get())
        except ValueError:
            limit = 8.0

        for row_id in self.tree.get_children():
            self.tree.delete(row_id)
        self.conclusion.configure(text="")
        self._stop_flag.clear()
        self.explore_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.start(12)

        def on_step(row):
            tag = "ok" if row["success"] else "fail"
            text = "✅ знайдено" if row["success"] else "❌ не знайдено (ліміт часу)"
            self.after(0, lambda: self.tree.insert(
                "", "end",
                values=(row["bits"], f'{row["elapsed"]:.3f}', text), tags=(tag,)))

        def work():
            return explore_feasibility(sizes, time_limit=limit, on_step=on_step,
                                        stop_flag=self._stop_flag)

        def done(results):
            self.progress.stop()
            self.explore_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            if not results:
                return
            last_ok = [r for r in results if r["success"]]
            if last_ok:
                max_ok_bits = max(r["bits"] for r in last_ok)
                self.conclusion.configure(
                    text=(f"Висновок: у цьому експерименті атака перебором дільників "
                          f"встигала спрацювати за {limit:.0f} с для N приблизно до "
                          f"{max_ok_bits} біт включно. Для розрядностей, що "
                          f"використовуються на практиці (1024–4096 біт), перебір "
                          f"дільників практично нездійсненний — потрібні спеціальні "
                          f"алгоритми факторизації (напр. решето числового поля) та "
                          f"значно більші обчислювальні ресурси."))
            else:
                self.conclusion.configure(
                    text="Навіть найменша перевірена розрядність виявилась завеликою "
                         "для заданого ліміту часу — спробуйте менші значення.")

        def error(exc):
            self.progress.stop()
            self.explore_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            messagebox.showerror("Помилка", str(exc))

        from .widgets import run_in_thread
        run_in_thread(self, work, on_done=done, on_error=error)

    def _stop_explore(self):
        self._stop_flag.set()
