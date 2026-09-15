"""Модуль для Завдання 3 (Безпечне хешування, CSV-база та JSON-логування)."""

import contextlib
import csv
import hashlib
import json
import os
import sys
from datetime import datetime

project_root = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../"),
)
sys.path.append(project_root)

from shared.student import VARIANT_NUMBER  # noqa: E402

MIN_PASSWORD_LENGTH = 16
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
USERS_FILE = os.path.join(DATA_DIR, 'users.csv')
LOG_FILE = os.path.join(DATA_DIR, 'log.json')


class ValidationError(Exception):
    """Власний виняток для помилок валідації пароля."""

    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує хеш пароля за допомогою алгоритму sha3_256 (Варіант 5)."""
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль закороткий. Мінімум {MIN_PASSWORD_LENGTH} симв.",
        )

    salted_password = password + salt
    return hashlib.sha3_256(salted_password.encode()).hexdigest()


def create_user(username: str, password: str) -> tuple:
    """Створює кортеж користувача з хешем пароля."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return (username, hash_value)


def create_users(users_list: tuple):
    """Записує список користувачів у CSV-файл."""
    os.makedirs(DATA_DIR, exist_ok=True)

    try:
        with open(USERS_FILE, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            for username, password in users_list:
                try:
                    user_data = create_user(username, password)
                    writer.writerow(user_data)
                except ValidationError as e:
                    print(f"Помилка створення {username}: {e}")
    except (OSError, PermissionError) as e:
        print(f"Помилка запису у файл бази даних: {e}")


def read_users_db() -> list:
    """Зчитує вміст CSV-файлу у список."""
    users_db = []
    try:
        with open(USERS_FILE, encoding='utf-8') as file:
            reader = csv.reader(file)
            print("\n--- База користувачів (users.csv) ---")
            print(f"{'Логін':<15} | {'Хеш'}")
            print("-" * 80)
            for row in reader:
                if row:
                    users_db.append(row)
                    print(f"{row[0]:<15} | {row[1]}")
    except FileNotFoundError:
        print("Файл бази даних не знайдено.")
    except (OSError, PermissionError) as e:
        print(f"Помилка читання файлу: {e}")
    return users_db


def log_event(func):
    """Декоратор для логування спроб входу у JSON-файл."""

    def wrapper(username: str, password: str, *args, **kwargs):
        try:
            result_bool = func(username, password, *args, **kwargs)
        except Exception:
            result_bool = False

        result_str = "success" if result_bool else "failure"

        log_entry = {
            "event": "login",
            "user": username,
            "result": result_str,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "args": args,
            "kwargs": kwargs,
        }

        os.makedirs(DATA_DIR, exist_ok=True)
        try:
            logs = []
            if os.path.exists(LOG_FILE):
                with (
                    open(LOG_FILE, encoding='utf-8') as file,
                    contextlib.suppress(json.JSONDecodeError),
                ):
                    logs = json.load(file)

            logs.append(log_entry)

            with open(LOG_FILE, mode='w', encoding='utf-8') as file:
                json.dump(logs, file, indent=4)
        except (OSError, PermissionError) as e:
            print(f"Помилка запису логу: {e}")

        return result_bool

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін та пароль користувача."""
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми.")

    users_db = read_users_db()

    try:
        expected_hash = generate_hash(password, PERSONAL_SALT)
    except ValidationError:
        return False

    for db_user, db_hash in users_db:
        if db_user == username and db_hash == expected_hash:
            return True
    return False


def run_task3():
    """Запускає виконання Завдання 3."""
    print("\n--- Завдання 3: Хешування та Авторизація ---")

    users_to_register = (
        ("admin", "SuperSecretPassword1234"),
        ("user1", "Short1"),
        ("cyber_sec", "CyberSecurityPolytech2026"),
        ("diana", "MySuperSecurePassword123"),
        ("hacker", "HackerPwned123456789"),
        ("manager", "ManagerPass!@#2026123"),
        ("staff", "StaffMemberPasswordHere"),
        ("student", "LvivPolytechSecurity2026"),
        ("test", "Test"),
        ("tester", "TesterPassword1234567"),
    )

    print("\n1. Створення бази користувачів...")
    create_users(users_to_register)

    print("\n2. Спроба входу (логується в log.json)...")
    try:
        is_diana_ok = login("diana", "MySuperSecurePassword123")
        status_diana = "Успіх" if is_diana_ok else "Відмовлено"
        print(f"Вхід 'diana' (правильний): {status_diana}")

        is_admin_ok = login("admin", "WrongPass12345")
        status_admin = "Успіх" if is_admin_ok else "Відмовлено"
        print(f"Вхід 'admin' (невірний): {status_admin}")
    except Exception as e:
        print(f"Системна помилка: {e}")
