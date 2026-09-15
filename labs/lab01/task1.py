"""Модуль для комплексного аналізу надійності паролів (Завдання 1)."""

import os
import random
import re
import sys

# Додаємо шлях до кореня проекту для імпорту shared
project_root = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../"),
)
sys.path.append(project_root)

from shared.student import VARIANT_NUMBER  # noqa: E402

# Дані 5 варіанту
passwords = [
    "DataS3cur3!", "123", "Crypto@Analysis", "test123", "Quantum#2023",
    "access", "Security@Pro", "password1", "Adv@nced123", "guest123",
]

criteria = {
    "min_length": 12,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "123", "test123", "access", "password1", "guest123", "admin",
}


def evaluate_password(pwd: str) -> str:
    """Визначає рівень надійності для одного пароля."""
    length = len(pwd)

    has_digit = True
    if criteria["require_digits"]:
        has_digit = bool(re.search(r'\d', pwd))

    has_upper = True
    if criteria["require_upper"]:
        has_upper = bool(re.search(r'[A-Z]', pwd))

    has_special = True
    if criteria["require_special"]:
        has_special = bool(re.search(r'[^a-zA-Z0-9]', pwd))

    has_lower = bool(re.search(r'[a-z]', pwd))

    meets_all = has_digit and has_upper and has_special
    meets_some = has_digit or has_upper or has_special or has_lower

    is_forbidden = (
            pwd in forbidden_passwords or length < criteria["min_length"]
    )
    is_unique = passwords.count(pwd) == 1

    # Замість status = ... використовуємо одразу return
    if is_forbidden:
        return "Заборонений"
    if meets_all and length >= criteria["min_length"] + 4 and is_unique:
        return "Дуже сильний"
    if meets_all and length < criteria["min_length"] + 4:
        return "Сильний"
    if length >= criteria["min_length"] and meets_some and not meets_all:
        return "Середній"
    if not is_forbidden and meets_some:
        return "Слабкий"

    return "Не визначено"


def analyze_passwords():
    """Генерує додаткові паролі та викликає їх оцінку."""
    print(f"\n--- Аналіз паролів (Варіант {VARIANT_NUMBER}) ---")

    max_idx = len(passwords) - 1
    indices = [random.randint(0, max_idx) for _ in range(3)]
    for idx in indices:
        passwords.append(passwords[idx])

    results = []

    # Тепер код виглядає дуже чисто!
    for pwd in passwords:
        status = evaluate_password(pwd)
        results.append((pwd, status))

    print(f"{'Пароль':<20} | {'Надійність'}")
    print("-" * 40)
    for pwd, status in results:
        print(f"{pwd:<20} | {status}")
