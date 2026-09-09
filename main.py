"""Лабораторна робота №1. Варіант 5."""
import csv
import hashlib
import json
import random
import re
from datetime import datetime
from pathlib import Path

# ============================================================
# ДАНІ СТУДЕНТА
# ============================================================

STUDENT_NAME = "Білянич Діана Романівна"
GROUP_NAME = "КБ-___"
VARIANT_NUMBER = 5


# ============================================================
# ЗАВДАННЯ 1
# КОМПЛЕКСНИЙ АНАЛІЗАТОР НАДІЙНОСТІ ПАРОЛІВ
# ============================================================

passwords = [
    "DataS3cur3!",
    "123",
    "Crypt0@Analysis",
    "test123",
    "Quantum#2023",
    "access",
    "Secur1ty@Pro",
    "password1",
    "Adv@nced123",
    "guest123",
]

criteria = {
    "min_length": 12,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "123",
    "test123",
    "access",
    "password1",
    "guest123",
    "admin",
}


def analyze_password(password, all_passwords):
    """Визначає рівень надійності пароля."""
    if (
        password in forbidden_passwords
        or len(password) < criteria["min_length"]
    ):
        return "Заборонений"

    has_digit = bool(re.search(r"\d", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    security_criteria = [
        has_digit,
        has_upper,
        has_special,
    ]

    criteria_count = sum(security_criteria)

    if criteria_count == 0:
        return "Слабкий"

    if criteria_count < 3: # noqa: PLR2004
        return "Середній"

    if len(password) < criteria["min_length"] + 4:
        return "Сильний"

    if all_passwords.count(password) == 1:
        return "Дуже сильний"

    return "Сильний"


def task1():
    """Виконує аналіз надійності паролів."""
    print("\n" + "=" * 70)
    print("ЗАВДАННЯ 1. АНАЛІЗАТОР НАДІЙНОСТІ ПАРОЛІВ")
    print("=" * 70)

    password_list = passwords.copy()

    # Генеруємо 3 випадкові індекси.
    random_indices = random.sample(
        range(len(password_list)),
        3,
    )

    # Додаємо дублікати вибраних паролів.
    for index in random_indices:
        password_list.append(password_list[index])

    print("\nДодані дублікати:")
    for index in random_indices:
        print(f"  {passwords[index]}")

    print("\nРезультати аналізу:")
    print("-" * 70)
    print(f"{'№':<4}{'Пароль':<25}{'Довжина':<10}{'Результат'}")
    print("-" * 70)

    for number, password in enumerate(password_list, start=1):
        result = analyze_password(password, password_list)

        print(
            f"{number:<4}{password:<25}{len(password):<10}{result}",
        )

    print("-" * 70)


# ============================================================
# ЗАВДАННЯ 2
# БАГАТОРІВНЕВА СИСТЕМА КОНТРОЛЮ ДОСТУПУ
# ============================================================

users = {
    "forensic_lead": {
        "role": "forensic_analyst",
        "clearance": 4,
        "department": "Forensics",
        "active": True,
    },
    "compliance_off": {
        "role": "compliance_officer",
        "clearance": 3,
        "department": "Compliance",
        "active": True,
    },
    "trainee_sec": {
        "role": "trainee",
        "clearance": 1,
        "department": "Training",
        "active": True,
    },
    "vendor_tech": {
        "role": "vendor_support",
        "clearance": 2,
        "department": "Vendor",
        "active": True,
    },
    "archived_usr": {
        "role": "archived",
        "clearance": 1,
        "department": "Archive",
        "active": False,
    },
}

resources = [
    ("forensic_images", 4),
    ("compliance_reports", 3),
    ("training_videos", 1),
    ("vendor_tools", 2),
    ("evidence_locker", 4),
    ("certification_docs", 1),
    ("audit_findings", 3),
    ("chain_of_custody", 4),
    ("support_tickets", 2),
    ("learning_modules", 1),
]

security_levels = (
    "Basic",
    "Standard",
    "Protected",
    "Maximum",
)

blocked_users = {
    "archived_usr",
    "terminated_vendor",
    "security_breach",
}


def check_access(username, _resource_name, resource_level):
    """Перевіряє доступ користувача до ресурсу."""
    if username not in users:
        return False, "User not found"

    if username in blocked_users:
        return False, "User is blocked"

    user = users[username]

    if user["active"] is False:
        return False, "Account inactive"

    if user["clearance"] >= resource_level:
        return True, "Access granted"

    return False, "Insufficient clearance"


def task2():
    """Виконує перевірку доступу користувачів."""
    print("\n" + "=" * 70)
    print("ЗАВДАННЯ 2. СИСТЕМА КОНТРОЛЮ ДОСТУПУ")
    print("=" * 70)

    print("\nРесурси системи:")
    print("-" * 60)

    for resource_name, level in resources:
        level_name = security_levels[level - 1]

        print(
            f"{resource_name:<25}рівень {level}: {level_name}",
        )

    print("\nПеревірка доступу:")
    print("-" * 70)

    for username in users:
        for resource_name, resource_level in resources:
            allowed, reason = check_access(
                username,
                resource_name,
                resource_level,
            )

            result = "ALLOW" if allowed else "DENY"

            print(
                f"user={username:<20} "
                f"resource={resource_name:<25} "
                f"-> {result} ({reason})",
            )


# ============================================================
# ЗАВДАННЯ 3
# ХЕШУВАННЯ, CSV-БАЗА ТА JSON-ЛОГУВАННЯ
# ============================================================

HASH_ALGORITHM = "sha3_256"
MIN_PASSWORD_LENGTH = 16

DATA_DIR = Path("labs") / "lab01" / "data"
USERS_FILE = DATA_DIR / "users.csv"
LOG_FILE = DATA_DIR / "log.json"


class ValidationError(Exception):
    """Помилка перевірки пароля."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Створює SHA3-256 хеш пароля разом із сіллю."""
    if not password or not salt:
        raise ValueError(
            "Пароль та сіль не можуть бути порожніми.",
        )

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль повинен містити мінімум {MIN_PASSWORD_LENGTH} символів.",
        )

    value = password + salt

    hash_object = hashlib.sha3_256(
        value.encode("utf-8"),
    )

    return hash_object.hexdigest()


def get_personal_salt():
    """Створює персональну сіль із номера варіанту."""
    return str(VARIANT_NUMBER).zfill(5)


users_to_register = (
    ("forensic_admin", "ForensicSecure2026!"),
    ("compliance_user", "ComplianceSecure16!"),
    ("security_analyst", "SecurityAnalysis16!"),
    ("audit_manager", "AuditManager2026!"),
    ("vendor_support", "VendorSupport2026!"),
    ("training_user", "TrainingPassword16!"),
    ("forensic_user", "ForensicPassword16!"),
    ("security_officer", "SecurityOfficer16!"),
    ("data_analyst", "DataAnalysis2026!!"),
    ("system_admin", "SystemAdministrator!"),
)


def create_user(username, password):
    """Створює запис користувача з хешем пароля."""
    salt = get_personal_salt()

    hash_value = generate_hash(
        password,
        salt,
    )

    return username, hash_value


def create_users(users_list):
    """Створює CSV-базу користувачів."""
    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        with open(
            USERS_FILE,
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.writer(file)

            for username, password in users_list:
                try:
                    user = create_user(
                        username,
                        password,
                    )

                    writer.writerow(user)

                except ValidationError as error:
                    print(
                        f"Помилка користувача {username}: {error}",
                    )

    except PermissionError:
        print("Помилка: немає дозволу на запис файлу.")

    except OSError as error:
        print(f"Помилка запису CSV: {error}")


def read_users():
    """Зчитує користувачів із CSV-файлу."""
    users_db = []

    try:
        with open(
            USERS_FILE,
            newline="",
            encoding="utf-8",
        ) as file:
            reader = csv.reader(file)

            for row in reader:
                if len(row) == 2:  # noqa: PLR2004
                    users_db.append(
                        (row[0], row[1]),
                    )

    except FileNotFoundError:
        print("Помилка: users.csv не знайдено.")

    except PermissionError:
        print("Помилка: немає дозволу на читання CSV.")

    except OSError as error:
        print(f"Помилка читання CSV: {error}")

    return users_db


def log_event(function):
    """Декоратор для журналювання спроб входу."""

    def wrapper(username, password):
        result = False

        try:
            result = function(
                username,
                password,
            )

        finally:
            DATA_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

            event = {
                "event": "login",
                "user": username,
                "result": ("success" if result else "failure"),
                "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S",
                ),
                "args": [],
                "kwargs": {},
            }

            logs = []

            try:
                if LOG_FILE.exists():
                    with open(
                        LOG_FILE,
                        encoding="utf-8",
                    ) as file:
                        logs = json.load(file)

            except (
                FileNotFoundError,
                json.JSONDecodeError,
            ):
                logs = []

            logs.append(event)

            try:
                with open(
                    LOG_FILE,
                    "w",
                    encoding="utf-8",
                ) as file:
                    json.dump(
                        logs,
                        file,
                        indent=4,
                        ensure_ascii=False,
                    )

            except PermissionError:
                print(
                    "Помилка: немає дозволу на запис журналу.",
                )

            except OSError as error:
                print(
                    f"Помилка запису log.json: {error}",
                )

        return result

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін та пароль користувача."""
    if not username or not password:
        raise ValueError(
            "Логін та пароль не можуть бути порожніми.",
        )

    users_db = read_users()

    salt = get_personal_salt()

    try:
        password_hash = generate_hash(
            password,
            salt,
        )

    except ValidationError as error:
        print(f"Помилка валідації: {error}")
        return False

    for stored_username, stored_hash in users_db:
        if stored_username == username:
            return password_hash == stored_hash

    return False


def print_users_db(users_db):
    """Виводить CSV-базу користувачів."""
    print("\nБаза користувачів:")
    print("-" * 90)
    print(f"{'Логін':<25}{'Хеш SHA3-256'}")
    print("-" * 90)

    for username, hash_value in users_db:
        print(
            f"{username:<25}{hash_value}",
        )

    print("-" * 90)


def task3():
    """Виконує хешування, CSV та автентифікацію."""
    print("\n" + "=" * 70)
    print("ЗАВДАННЯ 3. ХЕШУВАННЯ, CSV ТА JSON-ЛОГУВАННЯ")
    print("=" * 70)

    print(
        f"\nАлгоритм хешування: {HASH_ALGORITHM}",
    )

    print(
        f"Мінімальна довжина пароля: {MIN_PASSWORD_LENGTH}",
    )

    salt = get_personal_salt()

    print(
        f"Персональна сіль: {salt}",
    )

    # Створення CSV.
    create_users(users_to_register)

    # Читання CSV.
    users_db = read_users()

    print_users_db(users_db)

    # Тест успішної авторизації.
    print("\nТест авторизації:")

    test_username = "forensic_admin"
    test_password = "ForensicSecure2026!"

    try:
        result = login(
            test_username,
            test_password,
        )

        if result:
            print(
                f"{test_username}: LOGIN SUCCESS",
            )
        else:
            print(
                f"{test_username}: LOGIN FAILURE",
            )

    except ValueError as error:
        print(f"Помилка: {error}")

    # Тест неправильної авторизації.
    try:
        result = login(
            test_username,
            "WrongPassword123456!",
        )

        if result:
            print(
                f"{test_username}: LOGIN SUCCESS",
            )
        else:
            print(
                f"{test_username}: LOGIN FAILURE",
            )

    except ValueError as error:
        print(f"Помилка: {error}")

    # Тест неіснуючого користувача.
    try:
        result = login(
            "unknown_user",
            "ForensicSecure2026!",
        )

        if result:
            print(
                "unknown_user: LOGIN SUCCESS",
            )
        else:
            print(
                "unknown_user: LOGIN FAILURE",
            )

    except ValueError as error:
        print(f"Помилка: {error}")

    print(
        f"\nЖурнал подій збережено у: {LOG_FILE}",
    )


# ============================================================
# MAIN
# ============================================================


def main():
    """Головна функція лабораторної роботи."""
    print("=" * 70)
    print("ЛАБОРАТОРНА РОБОТА №1")
    print("Основи розробки на Python, Git та стандарти стилю коду")
    print("=" * 70)

    print(f"\nСтудент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")

    task1()
    task2()
    task3()

    print("\n" + "=" * 70)
    print("ЛАБОРАТОРНУ РОБОТУ ЗАВЕРШЕНО")
    print("=" * 70)


if __name__ == "__main__":
    main()
