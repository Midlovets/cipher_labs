"""Тести криптосистеми Тритеміуса. Запуск:  python -m unittest discover -v"""

import os
import random
import unittest

from trithemius import (BYTES, ENGLISH_26, UKRAINIAN_33, UKRAINIAN_35, AttackError, InvalidDataError,
                        InvalidKeyError, LinearKey, PhraseKey, QuadraticKey, TrithemiusCipher,
                        attack, verify_key)

TEXT_UA = "Шифр Тритеміуса — вдосконалений шифр Цезаря, де крок зміщення змінний. Привіт, світе!"
TEXT_EN = "The Trithemius cipher is an improved Caesar cipher with a variable shift."


class TestEncryption(unittest.TestCase):
    def test_linear_by_hand(self):
        # n = 26, k = 1*p + 2, p з 0: a(0)+2=c, b(1)+3=e, c(2)+4=g
        c = TrithemiusCipher(ENGLISH_26, LinearKey(1, 2))
        self.assertEqual(c.encrypt_text("abc"), "ceg")
        self.assertEqual(c.decrypt_text("ceg"), "abc")

    def test_first_position_one(self):
        # p з 1: a+3=d, b+4=f, c+5=h
        c = TrithemiusCipher(ENGLISH_26, LinearKey(1, 2), first_position=1)
        self.assertEqual(c.encrypt_text("abc"), "dfh")

    def test_quadratic_by_hand(self):
        # k = p^2 + p + 1: p=0 ->1, p=1 ->3, p=2 ->7 ; a+1=b, a+3=d, a+7=h
        c = TrithemiusCipher(ENGLISH_26, QuadraticKey(1, 1, 1))
        self.assertEqual(c.encrypt_text("aaa"), "bdh")

    def test_phrase_by_hand(self):
        # гасло «bc»: зсуви 1, 2, 1, 2 ; a+1=b, a+2=c ...
        c = TrithemiusCipher(ENGLISH_26, PhraseKey("bc"))
        self.assertEqual(c.encrypt_text("aaaa"), "bcbc")

    def test_wraparound(self):
        c = TrithemiusCipher(ENGLISH_26, LinearKey(0, 3))
        self.assertEqual(c.encrypt_text("xyz"), "abc")

    def test_negative_coefficients(self):
        c = TrithemiusCipher(UKRAINIAN_33, LinearKey(-4, -9))
        self.assertTrue(c.round_trip_ok(TEXT_UA))

    def test_round_trip_all_key_types_all_alphabets(self):
        keys = [LinearKey(7, 11), QuadraticKey(3, 5, 8), PhraseKey("ключ")]
        for alphabet, text in [(UKRAINIAN_33, TEXT_UA), (UKRAINIAN_35, TEXT_UA), (ENGLISH_26, TEXT_EN)]:
            for key in keys:
                if isinstance(key, PhraseKey) and alphabet is ENGLISH_26:
                    key = PhraseKey("secret")
                for start in (0, 1):
                    c = TrithemiusCipher(alphabet, key, first_position=start)
                    enc = c.encrypt_text(text)
                    self.assertNotEqual(enc, text)
                    expected = text if alphabet.keeps_case else text.lower()
                    self.assertEqual(c.decrypt_text(enc), expected, (alphabet.name, key, start))

    def test_case_and_foreign_symbols_preserved(self):
        c = TrithemiusCipher(ENGLISH_26, LinearKey(2, 5))
        text = "Hello, World! 123 Привіт"
        enc = c.encrypt_text(text)
        self.assertEqual(len(enc), len(text))
        self.assertTrue(enc[0].isupper() and enc[7].isupper())
        self.assertEqual(enc[5:7], ", ")
        self.assertEqual(enc[-6:], "Привіт")      # кирилиця поза англійським алфавітом
        self.assertEqual(c.decrypt_text(enc), text)

    def test_non_letters_do_not_advance_position(self):
        c = TrithemiusCipher(ENGLISH_26, LinearKey(1, 0))
        self.assertEqual(c.encrypt_text("a b"), "a c")   # p: a=0, b=1

    def test_ukrainian_35_encrypts_space(self):
        c = TrithemiusCipher(UKRAINIAN_35, LinearKey(1, 1))
        self.assertNotIn(" ", c.encrypt_text("а а а а"))

    def test_35_alphabet_lowercases(self):
        c = TrithemiusCipher(UKRAINIAN_35, LinearKey(5, 7))
        self.assertEqual(c.decrypt_text(c.encrypt_text("Привіт Світе")), "привіт світе")

    def test_bytes_round_trip(self):
        data = bytes(random.Random(1).randrange(256) for _ in range(5000))
        for key in (LinearKey(13, 200), QuadraticKey(5, 77, 255), PhraseKey("пароль")):
            c = TrithemiusCipher(BYTES, key)
            enc = c.encrypt_bytes(data)
            self.assertNotEqual(enc, data)
            self.assertEqual(c.decrypt_bytes(enc), data)

    def test_file_round_trip(self):
        import tempfile
        raw = os.urandom(3000)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.bin")
            with open(p, "wb") as f:
                f.write(raw)
            c = TrithemiusCipher(BYTES, LinearKey(9, 4))
            with open(p, "rb") as f:
                enc = c.encrypt_bytes(f.read())
            with open(p + ".enc", "wb") as f:
                f.write(enc)
            with open(p + ".enc", "rb") as f:
                self.assertEqual(c.decrypt_bytes(f.read()), raw)


class TestValidation(unittest.TestCase):
    def test_key_non_integer(self):
        for key in (LinearKey(1.5, 2), LinearKey("a", 2), LinearKey(True, 2), QuadraticKey(1, None, 3)):
            with self.assertRaises(InvalidKeyError):
                TrithemiusCipher(ENGLISH_26, key)

    def test_zero_shift_key_rejected(self):
        with self.assertRaises(InvalidKeyError):
            TrithemiusCipher(ENGLISH_26, LinearKey(26, 52))
        with self.assertRaises(InvalidKeyError):
            TrithemiusCipher(UKRAINIAN_33, QuadraticKey(33, 0, 66))

    def test_phrase_validation(self):
        for bad in ("", "abc1", "ключ"):                     # порожнє, цифра, кирилиця для EN
            with self.assertRaises(InvalidKeyError):
                TrithemiusCipher(ENGLISH_26, PhraseKey(bad))
        with self.assertRaises(InvalidKeyError):
            TrithemiusCipher(ENGLISH_26, PhraseKey("aaa"))   # лише нульові зсуви
        TrithemiusCipher(ENGLISH_26, PhraseKey("SeCrEt"))    # регістр не важливий

    def test_empty_and_foreign_text(self):
        c = TrithemiusCipher(ENGLISH_26, LinearKey(1, 1))
        for bad in ("", "   ", "12345 !?", "привіт"):
            with self.assertRaises(InvalidDataError):
                c.encrypt_text(bad)
        with self.assertRaises(InvalidDataError):
            c.encrypt_bytes(b"x")                            # текстовий алфавіт != байти

    def test_first_position_validation(self):
        with self.assertRaises(ValueError):
            TrithemiusCipher(ENGLISH_26, LinearKey(1, 1), first_position=2)

    def test_validate_encryption_and_decryption(self):
        c = TrithemiusCipher(UKRAINIAN_33, QuadraticKey(2, 3, 4))
        enc = c.encrypt_text(TEXT_UA)
        self.assertTrue(c.validate_encryption(TEXT_UA, enc))
        self.assertTrue(c.validate_decryption(enc, TEXT_UA))
        broken = enc[:10] + ("а" if enc[10] != "а" else "б") + enc[11:]
        r = c.validate_encryption(TEXT_UA, broken)
        self.assertFalse(r)
        self.assertIn("№11", r.message)
        self.assertFalse(c.validate_encryption(TEXT_UA, enc[:-1]))
        self.assertFalse(c.validate_decryption(broken, TEXT_UA))


class TestAttack(unittest.TestCase):
    def _recover(self, alphabet, key, text, start=0):
        enc = TrithemiusCipher(alphabet, key, start).encrypt_text(text)
        results = attack(alphabet, text, enc, start)
        return enc, results

    def test_linear_recovered_exactly(self):
        rng = random.Random(7)
        for alphabet, text in [(UKRAINIAN_33, TEXT_UA), (UKRAINIAN_35, TEXT_UA), (ENGLISH_26, TEXT_EN)]:
            for start in (0, 1):
                for _ in range(40):
                    n = alphabet.n
                    key = LinearKey(rng.randrange(1, n), rng.randrange(n))
                    enc, results = self._recover(alphabet, key, text, start)
                    found = [r.key for r in results if r.kind == "linear"]
                    self.assertEqual(found, [key])
                    self.assertTrue(all(verify_key(alphabet, r.key, text, enc, start) for r in results if r.key))

    def test_negative_or_large_coefficients_reduce_mod_n(self):
        enc, results = self._recover(ENGLISH_26, LinearKey(-3, 100), TEXT_EN)
        lin = [r.key for r in results if r.kind == "linear"][0]
        self.assertEqual((lin.A, lin.B), (-3 % 26, 100 % 26))

    def test_quadratic_recovered_and_equivalent(self):
        rng = random.Random(11)
        for alphabet, text in [(UKRAINIAN_33, TEXT_UA), (ENGLISH_26, TEXT_EN)]:
            for start in (0, 1):
                for _ in range(40):
                    n = alphabet.n
                    key = QuadraticKey(rng.randrange(1, n), rng.randrange(n), rng.randrange(n))
                    enc, results = self._recover(alphabet, key, text, start)
                    cands = [r.key for r in results if r.kind == "quadratic"]
                    self.assertTrue(cands, key)
                    # будь-який кандидат шифрує так само
                    for k in cands:
                        self.assertTrue(verify_key(alphabet, k, text, enc, start))
                    if n % 2:                                  # n непарне -> ключ єдиний
                        self.assertEqual(cands, [key])
                    else:
                        self.assertIn(key, cands)

    def test_phrase_recovered(self):
        for alphabet, phrase, text in [(UKRAINIAN_33, "ключ", TEXT_UA), (ENGLISH_26, "secret", TEXT_EN)]:
            enc, results = self._recover(alphabet, PhraseKey(phrase), text)
            ph = [r for r in results if r.kind == "phrase"][0]
            self.assertEqual(ph.key, PhraseKey(phrase))
            self.assertTrue(ph.reliable)

    def test_short_text_phrase_marked_unreliable(self):
        enc, results = self._recover(ENGLISH_26, PhraseKey("secretword"), "hello wor")
        ph = [r for r in results if r.kind == "phrase"][0]
        self.assertFalse(ph.reliable)

    def test_bytes_attack(self):
        data = os.urandom(300)
        for key in (LinearKey(17, 33), QuadraticKey(9, 4, 250), PhraseKey("пароль")):
            enc = TrithemiusCipher(BYTES, key).encrypt_bytes(data)
            results = attack(BYTES, data, enc)
            kinds = {r.kind: r for r in results}
            self.assertTrue(any(verify_key(BYTES, r.key, data, enc) for r in results if r.key))
            if key.kind == "phrase":
                self.assertEqual(kinds["phrase"].key, key)

    def test_attack_errors(self):
        with self.assertRaises(AttackError):
            attack(ENGLISH_26, "abc", "ab")                # різна довжина
        with self.assertRaises(AttackError):
            attack(ENGLISH_26, "abc", "abc")               # нульові зсуви
        with self.assertRaises(AttackError):
            attack(ENGLISH_26, "123", "123")               # немає літер
        with self.assertRaises(AttackError):
            attack(ENGLISH_26, "a-b", "b+c")               # змінено символ поза алфавітом
        with self.assertRaises(AttackError):
            attack(ENGLISH_26, "Ab", "bc")                 # регістр не збігається

    def test_too_short_for_models(self):
        res = attack(ENGLISH_26, "ab", "bd")               # лише 2 літери: лінійна і гасло
        self.assertEqual({r.kind for r in res}, {"linear", "phrase"})


if __name__ == "__main__":
    unittest.main()
