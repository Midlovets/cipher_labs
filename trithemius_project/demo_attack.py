"""Консольна демонстрація шифрування та атаки (без GUI):  python demo_attack.py"""

from trithemius import (UKRAINIAN_33, LinearKey, PhraseKey, QuadraticKey, TrithemiusCipher, attack,
                        verify_key)

plain = "Шифр Тритеміуса — вдосконалений шифр Цезаря зі змінним кроком зміщення."

for key in (LinearKey(7, 11), QuadraticKey(3, 5, 8), PhraseKey("ключ")):
    cipher = TrithemiusCipher(UKRAINIAN_33, key)
    enc = cipher.encrypt_text(plain)
    print(f"\nСправжній ключ: {key.describe()}")
    print(f"Шифртекст:      {enc}")
    print("Атака (відомі plain + cipher):")
    for r in attack(UKRAINIAN_33, plain, enc):
        ok = r.key is not None and verify_key(UKRAINIAN_33, r.key, plain, enc)
        print(f"  - {r}  -> {'✓' if ok else '✗'}")
