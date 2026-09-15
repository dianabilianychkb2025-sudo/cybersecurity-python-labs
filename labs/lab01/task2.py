"""Модуль для виконання Завдання 2 (Багаторівнева система контролю)."""

# Дані 5 варіанту
users = {
    "forensic_lead": {
        "role": "forensic_analyst", "clearance": 4,
        "department": "Forensics", "active": True,
    },
    "compliance_off": {
        "role": "compliance_officer", "clearance": 3,
        "department": "Compliance", "active": True,
    },
    "trainee_sec": {
        "role": "trainee", "clearance": 1,
        "department": "Training", "active": True,
    },
    "vendor_tech": {
        "role": "vendor_support", "clearance": 2,
        "department": "Vendor", "active": True,
    },
    "archived_usr": {
        "role": "archived", "clearance": 1,
        "department": "Archive", "active": False,
    },
}

resources = [
    ("forensic_images", 4), ("compliance_reports", 3), ("training_videos", 1),
    ("vendor_tools", 2), ("evidence_locker", 4), ("certification_docs", 1),
    ("audit_findings", 3), ("chain_of_custody", 4), ("support_tickets", 2),
    ("learning_modules", 1),
]

security_levels = ("Basic", "Standard", "Protected", "Maximum")
blocked_users = {"archived_usr", "terminated_vendor", "security_breach"}


def check_access():
    """Перевіряє права доступу користувачів до ресурсів."""
    print("\n--- Ресурси системи (Завдання 2) ---")

    for res_name, res_level in resources:
        level_name = security_levels[res_level - 1]
        print(f"Ресурс: {res_name}, Рівень: {level_name}")

    print("\n--- Результати перевірки доступу ---")

    users_to_check = list(users.keys()) + ["unknown_user"]

    for username in users_to_check:
        for res_name, res_level in resources:
            if username not in users:
                status = "DENY (User not found)"
            elif username in blocked_users:
                status = "DENY (User is blocked)"
            elif not users[username]["active"]:
                status = "DENY (Account inactive)"
            elif users[username]["clearance"] >= res_level:
                status = "ALLOW"
            else:
                status = "DENY (Insufficient clearance)"

            print(f"user={username} resource={res_name} -> {status}")
