"""Модуль управління користувачами, сесіями та журналами аудиту."""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

SESSION_TIMEOUT_SEC = 900
PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 16


class User:
    """Клас користувача із валідацією email та збереженням пароля."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
    ) -> None:
        """Ініціалізація екземпляра користувача."""
        self.username = username
        self._email = ""
        self.email = email
        self.role = role
        self.active = active
        self.__password_salt: bytes = b""
        self.__password_hash: bytes = b""

    @property
    def email(self) -> str:
        """Отримати email користувача."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Встановити email користувача після перевірки формату."""
        pattern = (
            r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}@"
            r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        )
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email: {value}")
        self._email = value

    def set_password(self, password: str) -> None:
        """Хешування та збереження пароля користувача з сіллю."""
        self.__password_salt = os.urandom(SALT_SIZE)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевірка відповідності введеного пароля збереженому хешу."""
        if not self.__password_hash or not self.__password_salt:
            return False
        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, calculated_hash)

    def deactivate(self) -> None:
        """Деактивація облікового запису користувача."""
        self.active = False

    def __str__(self) -> str:
        """Текстове представлення користувача."""
        status = "Active" if self.active else "Inactive"
        return (
            f"User({self.username}, Email: {self.email}, "
            f"Role: {self.role}, Status: {status})"
        )


class Admin(User):
    """Клас адміністратора, що успадковує User."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions: list[str] | set[str] | None = None,
    ) -> None:
        """Ініціалізація адміністратора з можливістю задати дозволи."""
        super().__init__(username, email, role="admin")
        self.permissions: set[str] = (
            set(permissions) if permissions else set()
        )

    def grant_permission(self, permission: str) -> None:
        """Надати дозвіл адміністратору."""
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Забрати дозвіл у адміністратора."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевірити наявність дозволу в адміністратора."""
        return permission in self.permissions

    def __str__(self) -> str:
        """Текстове представлення адміністратора."""
        base_str = super().__str__()
        return f"{base_str}, Permissions: {list(self.permissions)}"


class Session:
    """Модель сесії у часовому поясі UTC."""

    def __init__(self, ip: str) -> None:
        """Ініціалізація нового сеансу для заданої IP-адреси."""
        self.ip = ip
        now = datetime.now(timezone.utc)
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        """Оновити час останньої активності в сесії."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевірити, чи активна сесія (чи не вичерпано таймаут)."""
        if timeout_sec <= 0:
            raise ValueError("Timeout має бути позитивним числом")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity) < timedelta(seconds=timeout_sec)


@dataclass
class AuditLogEntry:
    """Датаклас окремого запису аудиту."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал подій безпеки."""

    def __init__(self) -> None:
        """Ініціалізація порожнього журналу аудиту."""
        self.logs: list[AuditLogEntry] = []

    def add_log(self, username: str, action: str) -> None:
        """Додати новий запис до журналу аудиту."""
        entry = AuditLogEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self.logs.append(entry)

    def show_all(self) -> list[AuditLogEntry]:
        """Отримати список усіх записів аудиту."""
        return self.logs


class UserAccount:
    """Клас облікового запису (композиція User, Session, AuditLog)."""

    def __init__(self, user: User, audit_log: AuditLog | None = None) -> None:
        """Ініціалізація акаунту користувача із прив'язаним журналом."""
        self.user = user
        self.session: Session | None = None
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, password: str, ip: str) -> bool:
        """Спроба аутентифікації користувача та створення сеансу."""
        if not self.user.active:
            self.audit_log.add_log(
                self.user.username,
                "login_failure (user_inactive)",
            )
            return False

        if self.user.check_password(password):
            self.session = Session(ip)
            self.session.touch()
            self.audit_log.add_log(self.user.username, "login_success")
            return True

        self.audit_log.add_log(self.user.username, "login_failure")
        return False

    def is_authenticated(self) -> bool:
        """Перевірити, чи автентифікований користувач із сесією."""
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        """Завершення поточного сеансу користувача."""
        if self.session:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str):
        """Доступ до атрибутів акаунту через дужки."""
        allowed = {
            "user": self.user,
            "session": self.session,
            "audit_log": self.audit_log,
        }
        if key in allowed:
            return allowed[key]
        raise KeyError(f"Ключ '{key}' недоступний.")

    def __setitem__(self, key: str, value):
        """Зміна атрибутів акаунту через дужки."""
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення має бути екземпляром User")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError(
                    "Значення має бути екземпляром Session або None",
                )
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("Значення має бути екземпляром AuditLog")
            self.audit_log = value
        else:
            raise KeyError(f"Запис за ключем '{key}' заборонено.")
