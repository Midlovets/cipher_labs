"""Графічний інтерфейс криптосистеми Тритеміуса (tkinter)."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .alphabet import BYTES, TEXT_ALPHABETS
from .attack import AttackError, attack, verify_key
from .book_cipher import BookCipherError, PoemCipher, WordBookCipher
from .cipher import InvalidDataError, TrithemiusCipher
from .keys import InvalidKeyError, LinearKey, PhraseKey, QuadraticKey

KEY_LINEAR = "linear"
KEY_QUADRATIC = "quadratic"
KEY_PHRASE = "phrase"

# Ключовий вірш за замовчуванням (Т. Г. Шевченко «Садок вишневий коло хати»)
DEFAULT_POEM = (
    "Садок вишневий коло хати "
    "хрущі над вишнями гудуть "
    "плугатарі з плугами йдуть "
    "співають ідучи дівчата "
    "а матері вечерять ждуть"
)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Шифр Тритеміуса — Комп'ютерний практикум №2")
        self.geometry("900x760")
        self.minsize(780, 640)

        self.alphabet_var = tk.StringVar(value=TEXT_ALPHABETS[0].name)
        self.key_kind = tk.StringVar(value=KEY_LINEAR)
        self.start_var = tk.IntVar(value=0)
        self.a_var, self.b_var, self.c_var = tk.StringVar(value="3"), tk.StringVar(value="5"), tk.StringVar(value="1")
        self.phrase_var = tk.StringVar(value="ключ")
        self.status = tk.StringVar(value="Готово")

        # змінні для книжкового шифру
        self.poem_width_var = tk.IntVar(value=10)
        self.book_cipher_type = tk.StringVar(value="poem")  # poem | word

        self._build_settings()
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.tab_crypt = ttk.Frame(nb)
        self.tab_attack = ttk.Frame(nb)
        self.tab_book = ttk.Frame(nb)
        nb.add(self.tab_crypt, text="Шифрування / розшифрування")
        nb.add(self.tab_attack, text="Атака (відомий відкритий текст)")
        nb.add(self.tab_book, text="Книжковий шифр (Лаб. №3)")
        self._build_crypt_tab()
        self._build_attack_tab()
        self._build_book_tab()
        ttk.Label(self, textvariable=self.status, anchor="w", relief="sunken").pack(fill="x", side="bottom")
        self._update_key_fields()

    # ---------- побудова інтерфейсу ----------

    def _build_settings(self):
        box = ttk.LabelFrame(self, text="Параметри та ключ")
        box.pack(fill="x", padx=8, pady=8)

        row = ttk.Frame(box)
        row.pack(fill="x", padx=6, pady=4)
        ttk.Label(row, text="Алфавіт:").pack(side="left")
        ttk.Combobox(row, textvariable=self.alphabet_var, state="readonly", width=42,
                     values=[a.name for a in TEXT_ALPHABETS]).pack(side="left", padx=6)
        ttk.Label(row, text="Позиції p з:").pack(side="left", padx=(16, 4))
        ttk.Radiobutton(row, text="0", variable=self.start_var, value=0).pack(side="left")
        ttk.Radiobutton(row, text="1", variable=self.start_var, value=1).pack(side="left")

        kinds = ttk.Frame(box)
        kinds.pack(fill="x", padx=6)
        ttk.Label(kinds, text="Тип ключа:").pack(side="left")
        for text, val in (("Лінійний  k = A·p + B", KEY_LINEAR),
                          ("Нелінійний  k = A·p² + B·p + C", KEY_QUADRATIC),
                          ("Гасло", KEY_PHRASE)):
            ttk.Radiobutton(kinds, text=text, variable=self.key_kind, value=val,
                            command=self._update_key_fields).pack(side="left", padx=8)

        fields = ttk.Frame(box)
        fields.pack(fill="x", padx=6, pady=6)
        self.entries = {}
        for label, var, name in (("A", self.a_var, "A"), ("B", self.b_var, "B"), ("C", self.c_var, "C")):
            ttk.Label(fields, text=label + " =").pack(side="left")
            e = ttk.Entry(fields, textvariable=var, width=8)
            e.pack(side="left", padx=(2, 12))
            self.entries[name] = e
        ttk.Label(fields, text="Гасло:").pack(side="left", padx=(12, 2))
        e = ttk.Entry(fields, textvariable=self.phrase_var, width=24)
        e.pack(side="left")
        self.entries["phrase"] = e

    def _build_crypt_tab(self):
        t = self.tab_crypt
        ttk.Label(t, text="Вхідний текст:").pack(anchor="w", padx=6, pady=(6, 0))
        self.src = self._text_box(t, 9)
        bar = ttk.Frame(t)
        bar.pack(fill="x", padx=6, pady=6)
        ttk.Button(bar, text="Зашифрувати", command=self.do_encrypt).pack(side="left")
        ttk.Button(bar, text="Розшифрувати", command=self.do_decrypt).pack(side="left", padx=6)
        ttk.Button(bar, text="Перевірити коректність", command=self.do_validate).pack(side="left")
        ttk.Button(bar, text="⇅ Результат → вхід", command=self.swap).pack(side="left", padx=6)
        ttk.Button(bar, text="Відкрити .txt", command=self.open_text).pack(side="right")
        ttk.Button(bar, text="Зберегти результат", command=self.save_text).pack(side="right", padx=6)
        ttk.Label(t, text="Результат:").pack(anchor="w", padx=6)
        self.dst = self._text_box(t, 9)

        files = ttk.LabelFrame(t, text="Довільні файли (шифрування байтів, n = 256)")
        files.pack(fill="x", padx=6, pady=8)
        ttk.Button(files, text="Зашифрувати файл…", command=lambda: self.do_file(True)).pack(side="left", padx=6, pady=6)
        ttk.Button(files, text="Розшифрувати файл…", command=lambda: self.do_file(False)).pack(side="left")
        ttk.Label(files, text="  Використовується той самий ключ; для гасла — його UTF-8 байти.").pack(side="left")

    def _build_attack_tab(self):
        t = self.tab_attack
        ttk.Label(t, text="Відомий відкритий текст:").pack(anchor="w", padx=6, pady=(6, 0))
        self.atk_plain = self._text_box(t, 6)
        ttk.Label(t, text="Відповідний шифртекст:").pack(anchor="w", padx=6)
        self.atk_cipher = self._text_box(t, 6)
        bar = ttk.Frame(t)
        bar.pack(fill="x", padx=6, pady=6)
        ttk.Button(bar, text="Знайти ключ", command=self.do_attack).pack(side="left")
        ttk.Button(bar, text="Взяти пару з вкладки шифрування", command=self.take_pair).pack(side="left", padx=6)
        ttk.Label(t, text="Результат атаки (алфавіт і нумерація позицій — з параметрів вище):").pack(anchor="w", padx=6)
        self.atk_out = self._text_box(t, 10)

    @staticmethod
    def _text_box(parent, height):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, padx=6, pady=2)
        box = tk.Text(frame, height=height, wrap="word", undo=True)
        sb = ttk.Scrollbar(frame, command=box.yview)
        box.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        box.pack(side="left", fill="both", expand=True)
        return box

    # ---------- допоміжне ----------

    def _update_key_fields(self):
        kind = self.key_kind.get()
        self.entries["A"].configure(state="normal" if kind != KEY_PHRASE else "disabled")
        self.entries["B"].configure(state="normal" if kind != KEY_PHRASE else "disabled")
        self.entries["C"].configure(state="normal" if kind == KEY_QUADRATIC else "disabled")
        self.entries["phrase"].configure(state="normal" if kind == KEY_PHRASE else "disabled")

    def _alphabet(self):
        name = self.alphabet_var.get()
        return next(a for a in TEXT_ALPHABETS if a.name == name)

    def _make_key(self):
        kind = self.key_kind.get()
        if kind == KEY_PHRASE:
            return PhraseKey(self.phrase_var.get())
        try:
            a, b = int(self.a_var.get()), int(self.b_var.get())
            if kind == KEY_LINEAR:
                return LinearKey(a, b)
            return QuadraticKey(a, b, int(self.c_var.get()))
        except ValueError:
            raise InvalidKeyError("Коефіцієнти ключа мають бути цілими числами") from None

    def _cipher(self, alphabet=None):
        return TrithemiusCipher(alphabet or self._alphabet(), self._make_key(), self.start_var.get())

    def _error(self, msg):
        self.status.set("Помилка: " + msg)
        messagebox.showerror("Помилка", msg)

    @staticmethod
    def _get(box):
        return box.get("1.0", "end-1c")

    @staticmethod
    def _set(box, text):
        box.delete("1.0", "end")
        box.insert("1.0", text)

    # ---------- дії ----------

    def _run_text(self, encrypt: bool):
        try:
            c = self._cipher()
            text = self._get(self.src)
            result = c.encrypt_text(text) if encrypt else c.decrypt_text(text)
        except (InvalidKeyError, InvalidDataError) as e:
            self._error(str(e))
            return
        self._set(self.dst, result)
        self.status.set(f"{'Зашифровано' if encrypt else 'Розшифровано'}; {c.key.describe()}")

    def do_encrypt(self):
        self._run_text(True)

    def do_decrypt(self):
        self._run_text(False)

    def do_validate(self):
        """Перевіряє: чи результат у нижньому полі є коректним шифруванням/розшифруванням вхідного."""
        try:
            c = self._cipher()
            src, dst = self._get(self.src), self._get(self.dst)
            if not dst:
                raise InvalidDataError("Поле результату порожнє — спочатку зашифруйте або розшифруйте")
            r_enc = c.validate_encryption(src, dst)
            r_dec = c.validate_decryption(src, dst)
        except (InvalidKeyError, InvalidDataError) as e:
            self._error(str(e))
            return
        if r_enc:
            msg = "Результат — коректне шифрування вхідного тексту цим ключем."
        elif r_dec:
            msg = "Результат — коректне розшифрування вхідного тексту цим ключем."
        else:
            msg = f"Перевірка не пройдена.\nЯк шифрування: {r_enc.message}\nЯк розшифрування: {r_dec.message}"
        self.status.set(msg.splitlines()[0])
        (messagebox.showinfo if (r_enc or r_dec) else messagebox.showwarning)("Перевірка", msg)

    def swap(self):
        self._set(self.src, self._get(self.dst))
        self._set(self.dst, "")

    def open_text(self):
        path = filedialog.askopenfilename(filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._set(self.src, f.read())
        except (OSError, UnicodeDecodeError) as e:
            self._error(f"Не вдалося прочитати файл: {e}")

    def save_text(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Текстові файли", "*.txt")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._get(self.dst))
            self.status.set(f"Збережено: {path}")
        except OSError as e:
            self._error(f"Не вдалося зберегти файл: {e}")

    def do_file(self, encrypt: bool):
        src = filedialog.askopenfilename(title="Оберіть файл")
        if not src:
            return
        try:
            c = self._cipher(BYTES)
            with open(src, "rb") as f:
                data = f.read()
            result = c.encrypt_bytes(data) if encrypt else c.decrypt_bytes(data)
        except (InvalidKeyError, InvalidDataError, OSError) as e:
            self._error(str(e))
            return
        suggested = src + ".enc" if encrypt else (src[:-4] if src.endswith(".enc") else src + ".dec")
        dst = filedialog.asksaveasfilename(initialfile=suggested.split("/")[-1].split("\\")[-1])
        if not dst:
            return
        try:
            with open(dst, "wb") as f:
                f.write(result)
        except OSError as e:
            self._error(f"Не вдалося зберегти файл: {e}")
            return
        self.status.set(f"{'Зашифровано' if encrypt else 'Розшифровано'} файл ({len(data)} байт) → {dst}")

    def take_pair(self):
        self._set(self.atk_plain, self._get(self.src))
        self._set(self.atk_cipher, self._get(self.dst))

    def do_attack(self):
        alphabet = self._alphabet()
        plain, cipher = self._get(self.atk_plain), self._get(self.atk_cipher)
        try:
            if not plain or not cipher:
                raise AttackError("Заповніть обидва поля: відкритий текст і шифртекст")
            if not alphabet.keeps_case:
                plain, cipher = plain.lower(), cipher.lower()
            results = attack(alphabet, plain, cipher, self.start_var.get())
        except AttackError as e:
            self._error(str(e))
            return
        lines = [f"Алфавіт: {alphabet.name}, n = {alphabet.n}; позиції з {self.start_var.get()}; "
                 f"літер у парі: {sum(alphabet.try_index(ch) is not None for ch in plain)}", ""]
        for i, r in enumerate(results, 1):
            ok = r.key is not None and verify_key(alphabet, r.key, plain, cipher, self.start_var.get())
            lines.append(f"{i}. {r}")
            if r.key is not None:
                lines.append(f"    перевірка: ключ {'шифрує пару коректно ✓' if ok else 'НЕ відтворює пару ✗'}")
        self._set(self.atk_out, "\n".join(lines))
        self.status.set(f"Атака завершена: знайдено варіантів ключа — {len(results)}")

    # ===== Книжковий шифр — нова вкладка =====

    def _build_book_tab(self):
        t = self.tab_book

        # --- режим шифру
        mode_frame = ttk.LabelFrame(t, text="Режим книжкового шифру")
        mode_frame.pack(fill="x", padx=6, pady=(6, 0))
        ttk.Radiobutton(mode_frame, text="Віршований шифр (RR/CC)",
                        variable=self.book_cipher_type, value="poem",
                        command=self._book_mode_changed).pack(side="left", padx=8, pady=4)
        ttk.Radiobutton(mode_frame, text="Словесний книжковий шифр (дод. завдання)",
                        variable=self.book_cipher_type, value="word",
                        command=self._book_mode_changed).pack(side="left", padx=8, pady=4)
        # ширина таблиці (лише для poem)
        self._poem_width_frame = ttk.Frame(mode_frame)
        self._poem_width_frame.pack(side="left", padx=(20, 4))
        ttk.Label(self._poem_width_frame, text="Ширина таблиці:").pack(side="left")
        ttk.Spinbox(self._poem_width_frame, from_=2, to=30,
                    textvariable=self.poem_width_var, width=4).pack(side="left", padx=4)

        # --- ключовий текст (вірш)
        ttk.Label(t, text="Ключ (вірш / текст-ключ):").pack(anchor="w", padx=6, pady=(6, 0))
        self.book_key = self._text_box(t, 5)
        self.book_key.insert("1.0", DEFAULT_POEM)

        # --- кнопки
        bar = ttk.Frame(t)
        bar.pack(fill="x", padx=6, pady=4)
        ttk.Button(bar, text="Зашифрувати", command=self.book_encrypt).pack(side="left")
        ttk.Button(bar, text="Розшифрувати", command=self.book_decrypt).pack(side="left", padx=6)
        ttk.Button(bar, text="⇅ Результат → вхід", command=self.book_swap).pack(side="left")
        ttk.Button(bar, text="Показати таблицю ключа", command=self.book_show_table).pack(side="left", padx=6)

        # --- вхідний / вихідний текст
        pane = ttk.PanedWindow(t, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=6, pady=(0, 4))

        left = ttk.LabelFrame(pane, text="Вхідний текст")
        pane.add(left, weight=1)
        self.book_src = tk.Text(left, height=8, wrap="word", undo=True)
        sb_l = ttk.Scrollbar(left, command=self.book_src.yview)
        self.book_src.configure(yscrollcommand=sb_l.set)
        sb_l.pack(side="right", fill="y")
        self.book_src.pack(fill="both", expand=True, padx=2, pady=2)

        right = ttk.LabelFrame(pane, text="Результат")
        pane.add(right, weight=1)
        self.book_dst = tk.Text(right, height=8, wrap="word", undo=True)
        sb_r = ttk.Scrollbar(right, command=self.book_dst.yview)
        self.book_dst.configure(yscrollcommand=sb_r.set)
        sb_r.pack(side="right", fill="y")
        self.book_dst.pack(fill="both", expand=True, padx=2, pady=2)

    def _book_mode_changed(self):
        state = "normal" if self.book_cipher_type.get() == "poem" else "disabled"
        for w in self._poem_width_frame.winfo_children():
            try:
                w.configure(state=state)
            except tk.TclError:
                pass

    def _get_book_cipher(self):
        """Створює та повертає об'єкт PoemCipher або WordBookCipher."""
        key_text = self.book_key.get("1.0", "end-1c").strip()
        if not key_text:
            raise BookCipherError("Ключовий текст (вірш) порожній")
        mode = self.book_cipher_type.get()
        if mode == "poem":
            width = self.poem_width_var.get()
            return PoemCipher(key_text, width=width)
        else:
            return WordBookCipher(key_text)

    def book_encrypt(self):
        try:
            cipher = self._get_book_cipher()
            text = self.book_src.get("1.0", "end-1c")
            if not text:
                raise BookCipherError("Введіть текст для шифрування")
            result = cipher.encrypt(text)
        except BookCipherError as e:
            self._error(str(e))
            return
        self.book_dst.delete("1.0", "end")
        self.book_dst.insert("1.0", result)
        self.status.set(f"Зашифровано. {cipher.describe()}")

    def book_decrypt(self):
        try:
            cipher = self._get_book_cipher()
            text = self.book_src.get("1.0", "end-1c")
            if not text.strip():
                raise BookCipherError("Поле вхідного тексту порожнє — введіть шифрограму")
            result = cipher.decrypt(text)
        except BookCipherError as e:
            self._error(str(e))
            return
        self.book_dst.delete("1.0", "end")
        self.book_dst.insert("1.0", result)
        self.status.set(f"Розшифровано. {cipher.describe()}")

    def book_swap(self):
        src = self.book_src.get("1.0", "end-1c")
        dst = self.book_dst.get("1.0", "end-1c")
        self.book_src.delete("1.0", "end")
        self.book_src.insert("1.0", dst)
        self.book_dst.delete("1.0", "end")
        self.book_dst.insert("1.0", src)

    def book_show_table(self):
        """Показує діалог з таблицею ключа (лише для PoemCipher)."""
        try:
            cipher = self._get_book_cipher()
        except BookCipherError as e:
            self._error(str(e))
            return
        if not isinstance(cipher, PoemCipher):
            messagebox.showinfo("Таблиця", "Таблиця доступна лише для Віршованого шифру.")
            return
        win = tk.Toplevel(self)
        win.title(f"Ключова таблиця — {cipher.describe()}")
        win.geometry("700x440")
        frame = ttk.Frame(win)
        frame.pack(fill="both", expand=True, padx=8, pady=8)
        box = tk.Text(frame, wrap="none", font=("Courier New", 12))
        sb_y = ttk.Scrollbar(frame, command=box.yview)
        sb_x = ttk.Scrollbar(frame, orient="horizontal", command=box.xview)
        box.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        sb_y.pack(side="right", fill="y")
        sb_x.pack(side="bottom", fill="x")
        box.pack(fill="both", expand=True)
        box.insert("1.0", cipher.table_str())
        box.configure(state="disabled")
        chars_info = f"Символи у таблиці: {cipher.available_chars()}"
        ttk.Label(win, text=chars_info, anchor="w").pack(fill="x", padx=8, pady=(0, 6))


def main():
    App().mainloop()
