"""Головний модуль для запуску CLI-утиліт."""

import argparse

from labs.lab02.task1 import Admin, User, UserAccount
from labs.lab02.task2 import run_scanner


def demo():
    """Сценарій демонстрації для Завдання 1."""
    print("=== Демонстрація Завдання 1 (ООП та сесії) ===")

    user = User("j_doe", "john.doe@example.com")
    user.set_password("SecurePassword123!")
    print(f"Створено користувача: {user}")

    account = UserAccount(user)

    print("\n--- Спроба входу з невірним паролем ---")
    if not account.login("WrongPassword", "192.168.1.10"):
        print("Вхід відхилено (невірний пароль).")

    print("\n--- Спроба входу з правильним паролем ---")
    if account.login("SecurePassword123!", "192.168.1.10"):
        print(
            f"Успішний вхід! Аутентифіковано: {account.is_authenticated()}",
        )

    print("\n--- Перевірка валідації email (@property) ---")
    try:
        user.email = "invalid_email_format"
    except ValueError as e:
        print(f"Отримано очікувану помилку: {e}")

    print("\n--- Робота з класом Admin ---")
    admin_user = Admin("admin_alex", "alex.admin@corp.com")
    admin_user.grant_permission("READ_LOGS")
    print(f"Адміністратор: {admin_user}")

    print("\n--- Завершення сеансу ---")
    account.logout()
    print(f"Аутентифіковано після logout: {account.is_authenticated()}")

    print("\n--- Записи в журналі AuditLog ---")
    for log in account["audit_log"].show_all():
        ts = log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"[{ts}] {log.username} -> {log.action}")


def main():
    """Точка входу в програму."""
    parser = argparse.ArgumentParser(
        description="CLI-утиліти кібербезпеки (ЛР №2)",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        help="Доступні команди",
    )

    # Команда demo
    subparsers.add_parser("demo", help="Демонстрація Завдання 1")

    # Команда analyze
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Запуск сканера доступності портів",
    )
    analyze_parser.add_argument(
        "--targets",
        type=str,
        default="labs/lab02/data/targets.json",
        help="Шлях до JSON цілей",
    )
    analyze_parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Таймаут підключення в секундах",
    )
    analyze_parser.add_argument(
        "--out-csv",
        type=str,
        default="labs/lab02/data/scan_results.csv",
        help="Файл для експорту в CSV",
    )
    analyze_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Детальний вивід логів",
    )

    args = parser.parse_args()

    if args.command == "demo":
        demo()
    elif args.command == "analyze":
        run_scanner(
            args.targets,
            args.timeout,
            args.out_csv,
            args.verbose,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
