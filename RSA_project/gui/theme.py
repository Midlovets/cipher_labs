# -*- coding: utf-8 -*-
"""
gui.theme
=========
Централізоване налаштування кольорів, шрифтів та стилів ttk,
щоб інтерфейс виглядав цілісно і акуратно.
"""

from tkinter import ttk

PALETTE = {
    "bg": "#f4f6fa",
    "surface": "#ffffff",
    "primary": "#2f5fd6",
    "primary_dark": "#20429c",
    "accent": "#1f8a5c",
    "danger": "#c0392b",
    "text": "#1d2433",
    "muted": "#60697c",
    "border": "#d8dee8",
}

FONT_FAMILY = "Segoe UI"
FONT_MONO = "Consolas"


def apply_theme(root):
    root.configure(bg=PALETTE["bg"])

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure(".", background=PALETTE["bg"], foreground=PALETTE["text"],
                     font=(FONT_FAMILY, 10))

    style.configure("TFrame", background=PALETTE["bg"])
    style.configure("Surface.TFrame", background=PALETTE["surface"])

    style.configure("TLabel", background=PALETTE["bg"], foreground=PALETTE["text"])
    style.configure("Surface.TLabel", background=PALETTE["surface"], foreground=PALETTE["text"])
    style.configure("Header.TLabel", background=PALETTE["bg"],
                     font=(FONT_FAMILY, 16, "bold"), foreground=PALETTE["primary_dark"])
    style.configure("SubHeader.TLabel", background=PALETTE["bg"],
                     font=(FONT_FAMILY, 10), foreground=PALETTE["muted"])
    style.configure("SectionTitle.TLabel", background=PALETTE["surface"],
                     font=(FONT_FAMILY, 11, "bold"), foreground=PALETTE["text"])
    style.configure("Status.TLabel", background=PALETTE["bg"], font=(FONT_FAMILY, 9, "italic"))
    style.configure("Success.TLabel", foreground=PALETTE["accent"],
                     background=PALETTE["bg"], font=(FONT_FAMILY, 9, "bold"))
    style.configure("Danger.TLabel", foreground=PALETTE["danger"],
                     background=PALETTE["bg"], font=(FONT_FAMILY, 9, "bold"))

    style.configure("TLabelframe", background=PALETTE["surface"], bordercolor=PALETTE["border"])
    style.configure("TLabelframe.Label", background=PALETTE["surface"],
                     font=(FONT_FAMILY, 10, "bold"), foreground=PALETTE["primary_dark"])

    style.configure("TButton", padding=(10, 6), font=(FONT_FAMILY, 10))
    style.map("TButton", background=[("active", PALETTE["border"])])

    style.configure("Accent.TButton", padding=(12, 7), font=(FONT_FAMILY, 10, "bold"),
                     foreground="white", background=PALETTE["primary"])
    style.map("Accent.TButton",
              background=[("active", PALETTE["primary_dark"]), ("disabled", "#9fb1e0")])

    style.configure("Danger.TButton", padding=(10, 6), font=(FONT_FAMILY, 10, "bold"))

    style.configure("TNotebook", background=PALETTE["bg"], borderwidth=0)
    style.configure("TNotebook.Tab", padding=(14, 8), font=(FONT_FAMILY, 10))
    style.map("TNotebook.Tab",
              background=[("selected", PALETTE["surface"])],
              foreground=[("selected", PALETTE["primary_dark"])])

    style.configure("Treeview", rowheight=24, font=(FONT_FAMILY, 9),
                     background=PALETTE["surface"], fieldbackground=PALETTE["surface"])
    style.configure("Treeview.Heading", font=(FONT_FAMILY, 9, "bold"))

    style.configure("TEntry", padding=4)
    style.configure("TCombobox", padding=4)

    style.configure("Horizontal.TProgressbar", background=PALETTE["primary"],
                     troughcolor=PALETTE["border"])

    return style
