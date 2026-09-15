"""Головний файл для запуску Лабораторної роботи №1."""

import os
import sys

# Додаємо шлях до кореня проекту для імпорту shared
project_root = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../"),
)
sys.path.append(project_root)

from shared import student  # noqa: E402
from task1 import analyze_passwords  # noqa: E402
from task2 import check_access  # noqa: E402
from task3 import run_task3  # noqa: E402


def main():
    """Точка входу для запуску всіх завдань."""
    print("=========================================")
    print("Лабораторна робота №1")
    print(f"Виконала: {student.STUDENT_NAME}")
    print(f"Група: {student.GROUP_NAME}")
    print(f"Варіант: {student.VARIANT_NUMBER}")
    print("=========================================")

    # Виклик Завдання 1
    analyze_passwords()

    # Виклик Завдання 2
    check_access()

    # Виклик Завдання 3
    run_task3()

    print("\n=========================================")
    print("Виконання лабораторної роботи завершено.")
    print("=========================================")


if __name__ == "__main__":
    main()
