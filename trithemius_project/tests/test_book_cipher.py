"""Тести книжкового шифру — Лабораторна №3."""

import pytest

from trithemius.book_cipher import BookCipherError, PoemCipher, WordBookCipher

# Вірш за замовчуванням (Т. Г. Шевченко «Садок вишневий коло хати»)
NEKRASOV = (
    "Садок вишневий коло хати "
    "хрущі над вишнями гудуть "
    "плугатарі з плугами йдуть "
    "співають ідучи дівчата "
    "а матері вечерять ждуть"
)

# ───────────────────────── PoemCipher ─────────────────────────────────────────


class TestPoemCipherTable:
    """Перевірка побудови таблиці."""

    def test_table_shape_exact(self):
        cipher = PoemCipher(NEKRASOV, width=10)
        assert cipher.cols == 10
        # кожен рядок рівно 10 символів
        for row in cipher.table:
            assert len(row) == 10

    def test_table_no_empty_rows(self):
        cipher = PoemCipher(NEKRASOV, width=10)
        assert cipher.rows >= 1

    def test_short_key_raises(self):
        with pytest.raises(BookCipherError):
            PoemCipher("ab", width=10)  # текст коротший за width

    def test_empty_key_raises(self):
        with pytest.raises(BookCipherError):
            PoemCipher("", width=10)

    def test_width_too_small_raises(self):
        with pytest.raises(BookCipherError):
            PoemCipher(NEKRASOV, width=1)

    def test_available_chars_nonempty(self):
        cipher = PoemCipher(NEKRASOV, width=10)
        assert len(cipher.available_chars()) > 0


class TestPoemCipherEncryptDecrypt:
    """Шифрування та розшифрування (round-trip)."""

    def setup_method(self):
        self.cipher = PoemCipher(NEKRASOV, width=10)

    def test_encrypt_returns_codes(self):
        enc = self.cipher.encrypt("с")
        # має відповідати патерну RR/CC
        import re
        assert re.fullmatch(r"\d+/\d+", enc.strip()), f"Unexpected: {enc}"

    def test_decrypt_single_code(self):
        # знаємо, що «с» є у вірші — знайдемо де
        idx = self.cipher._index.get("с")
        assert idx, "буква «с» має бути у вірші Шевченка"
        r, c = idx[0]
        result = self.cipher.decrypt(f"{r}/{c}")
        assert result.lower() == "с"

    def test_roundtrip_letters(self):
        """decrypt(encrypt(text)) == text для літер що є у таблиці."""
        plaintext = "са"  # ці букви точно є у Шевченка
        enc = self.cipher.encrypt(plaintext)
        dec = self.cipher.decrypt(enc)
        assert dec.lower() == plaintext.lower()

    def test_roundtrip_missing_char(self):
        """Символи, яких немає у таблиці, передаються як є через <символ>."""
        plaintext = "а!б"
        enc = self.cipher.encrypt(plaintext)
        dec = self.cipher.decrypt(enc)
        assert dec.lower() == plaintext.lower()

    def test_multiple_options_for_same_letter(self):
        """Одна буква може мати кілька різних кодів (полісемія)."""
        enc1 = self.cipher.encrypt("а")
        enc2 = self.cipher.encrypt("а")
        # розшифрування обох має дати «а»
        assert self.cipher.decrypt(enc1).lower() == "а"
        assert self.cipher.decrypt(enc2).lower() == "а"

    def test_encrypt_empty_raises(self):
        with pytest.raises(BookCipherError):
            self.cipher.encrypt("")

    def test_decrypt_invalid_code_raises(self):
        with pytest.raises(BookCipherError):
            self.cipher.decrypt("999/999")

    def test_decrypt_bad_format_raises(self):
        with pytest.raises(BookCipherError):
            self.cipher.decrypt("abc")

    def test_roundtrip_phrase(self):
        """Шифрування фрази та зворотне розшифрування."""
        # тільки букви що є у таблиці
        text = "слава"
        enc = self.cipher.encrypt(text)
        dec = self.cipher.decrypt(enc)
        assert dec.lower() == text.lower()


class TestPoemCipherTableStr:
    """Перевірка відображення таблиці."""

    def test_table_str_contains_coord_headers(self):
        cipher = PoemCipher(NEKRASOV, width=10)
        s = cipher.table_str()
        assert "01" in s   # заголовок стовпця 1
        assert "01 |" in s  # перший рядок

    def test_describe_contains_dimensions(self):
        cipher = PoemCipher(NEKRASOV, width=10)
        d = cipher.describe()
        assert "10" in d


# ─────────────────────── WordBookCipher ────────────────────────────────────────


KEY_TEXT = (
    "Садок вишневий коло хати "
    "хрущі над вишнями гудуть "
    "плугатарі з плугами йдуть "
    "співають ідучи дівчата "
    "а матері вечерять ждуть"
)


class TestWordBookCipherBasic:
    """Базові тести словесного книжкового шифру."""

    def setup_method(self):
        self.cipher = WordBookCipher(KEY_TEXT)

    def test_key_size_positive(self):
        assert self.cipher.key_size > 0

    def test_encrypt_returns_numbers(self):
        enc = self.cipher.encrypt("с")
        assert enc.isdigit(), f"Expected digit token, got: {enc}"

    def test_encrypt_space_gives_underscore(self):
        enc = self.cipher.encrypt("а б")
        tokens = enc.split()
        assert "_" in tokens

    def test_decrypt_underscore_gives_space(self):
        result = self.cipher.decrypt("_ 1")
        assert result[0] == " "

    def test_roundtrip_letter(self):
        """Для наявної літери decrypt(encrypt(letter))[0] == letter."""
        # «с» — перша буква «Садок» (слово 1 у ключі)
        enc = self.cipher.encrypt("с")
        dec = self.cipher.decrypt(enc)
        assert dec.lower() == "с"

    def test_encrypt_empty_raises(self):
        with pytest.raises(BookCipherError):
            self.cipher.encrypt("")

    def test_decrypt_invalid_token_raises(self):
        with pytest.raises(BookCipherError):
            self.cipher.decrypt("xyz")

    def test_decrypt_out_of_range_raises(self):
        with pytest.raises(BookCipherError):
            self.cipher.decrypt("99999")

    def test_empty_key_raises(self):
        with pytest.raises(BookCipherError):
            WordBookCipher("")

    def test_describe(self):
        d = self.cipher.describe()
        assert "словесний" in d.lower() or "книжковий" in d.lower()

    def test_missing_letter_wrapped(self):
        """Символ, якого немає у ключі → <символ>."""
        # Символ що точно не є першою буквою жодного слова
        enc = self.cipher.encrypt("ф")
        assert enc == "<ф>"
        dec = self.cipher.decrypt(enc)
        assert dec == "ф"
