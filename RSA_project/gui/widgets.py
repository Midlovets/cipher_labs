# -*- coding: utf-8 -*-
"""
gui.widgets
===========
Невеликі перевикористовувані будівельні блоки інтерфейсу:
  - card(): ttk.LabelFrame у стилі "картки" на білому тлі;
  - MonoText: текстове поле моноширинним шрифтом + кнопка "Копіювати";
  - run_in_thread(): виконання довгої операції у фоновому потоці
    без заморожування вікна (генерація ключів, дослідження атаки).
"""

import threading
import tkinter as tk
from tkinter import ttk

from .theme import PALETTE, FONT_MONO


def card(parent, title):
    """Створює LabelFrame-"картку" з заголовком та внутрішнім відступом."""
    frame = ttk.LabelFrame(parent, text=title, padding=12)
    return frame


class MonoText(ttk.Frame):
    """Текстове поле моноширинним шрифтом з кнопкою копіювання вмісту."""

    def __init__(self, parent, height=6, copy_label="Копіювати", **kwargs):
        super().__init__(parent, **kwargs)
        self.text = tk.Text(self, height=height, font=(FONT_MONO, 10), wrap="word",
                             relief="solid", borderwidth=1, padx=6, pady=6)
        self.text.pack(fill="both", expand=True)

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(4, 0))
        self.copy_btn = ttk.Button(bar, text="📋 " + copy_label, command=self._copy)
        self.copy_btn.pack(side="right")
        self.hint = ttk.Label(bar, text="", style="Success.TLabel")
        self.hint.pack(side="right", padx=8)

    def _copy(self):
        content = self.text.get("1.0", "end").rstrip("\n")
        self.clipboard_clear()
        self.clipboard_append(content)
        self.hint.configure(text="Скопійовано ✓")
        self.after(1500, lambda: self.hint.configure(text=""))

    def set(self, value: str):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", value)

    def get(self) -> str:
        return self.text.get("1.0", "end").rstrip("\n")

    def clear(self):
        self.set("")


def run_in_thread(widget, work, on_done=None, on_error=None):
    """
    Запускає work() у фоновому потоці, а on_done(result)/on_error(exc)
    викликає у головному потоці Tkinter через widget.after(0, ...).
    """

    def target():
        try:
            result = work()
        except Exception as exc:  # noqa: BLE001
            if on_error:
                widget.after(0, lambda: on_error(exc))
            return
        if on_done:
            widget.after(0, lambda: on_done(result))

    t = threading.Thread(target=target, daemon=True)
    t.start()
    return t
