from typing import Optional, Tuple

from passlib.hash import argon2

from app.config import config

# Настройка Argon2 с параметрами из конфигурации
argon2_context = argon2.using(
    time_cost=config.ARGON2_TIME_COST,
    memory_cost=config.ARGON2_MEMORY_COST,
    parallelism=config.ARGON2_PARALLELISM,
    hash_len=config.ARGON2_HASH_LEN,
    salt_len=config.ARGON2_SALT_LEN,
)


class SecurityConfig:
    """Класс с настройками безопасности, инициализируемый из config."""
    # Pepper - дополнительный секрет, который добавляется к паролю перед хешированием
    PASSWORD_PEPPER: str = config.PASSWORD_PEPPER

    # Параметры для Argon2
    ARGON2_TIME_COST: int = config.ARGON2_TIME_COST
    ARGON2_MEMORY_COST: int = config.ARGON2_MEMORY_COST
    ARGON2_PARALLELISM: int = config.ARGON2_PARALLELISM
    ARGON2_HASH_LEN: int = config.ARGON2_HASH_LEN
    ARGON2_SALT_LEN: int = config.ARGON2_SALT_LEN

    # Параметры для токенов
    ACCESS_TOKEN_EXPIRE_MINUTES: int = config.ACCESS_TOKEN_EXPIRE_MINUTES
    REFRESH_TOKEN_EXPIRE_DAYS: int = config.REFRESH_TOKEN_EXPIRE_DAYS

    # Секретный ключ для сессий
    SESSION_SECRET_KEY: str = config.SESSION_SECRET_KEY

    # CORS настройки
    CORS_ORIGINS: list = config.CORS_ORIGINS


# Создаем экземпляр конфигурации безопасности
security_config = SecurityConfig()


def get_password_hash(password: str) -> str:
    """
    Хеширует пароль с использованием Argon2id и добавлением перца.
    Args:
        password: Пароль в виде строки
    Returns:
        Хеш пароля
    """
    # Добавление перца к паролю перед хешированием
    peppered_password = f"{password}{security_config.PASSWORD_PEPPER}"
    return argon2_context.hash(peppered_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверяет пароль с использованием Argon2id и перца.
    Args:
        plain_password: Пароль в виде строки
        hashed_password: Хеш пароля из базы данных
    Returns:
        True если пароль верный, иначе False
    """
    # Добавление перца к проверяемому паролю
    peppered_password = f"{plain_password}{security_config.PASSWORD_PEPPER}"
    return argon2_context.verify(peppered_password, hashed_password)


def password_meets_requirements(password: str) -> Tuple[bool, Optional[str]]:
    """
    Проверяет соответствие пароля требованиям безопасности.
    Args:
        password: Пароль для проверки
    Returns:
        Tuple[bool, Optional[str]]: (Соответствует ли пароль требованиям, Сообщение об ошибке)
    """
    # Минимальная длина пароля
    if len(password) < 8:
        return False, "Пароль должен содержать не менее 8 символов"

    # Проверка наличия цифр
    if not any(char.isdigit() for char in password):
        return False, "Пароль должен содержать хотя бы одну цифру"

    # Проверка наличия букв в верхнем регистре
    if not any(char.isupper() for char in password):
        return False, "Пароль должен содержать хотя бы одну заглавную букву"

    # Проверка наличия букв в нижнем регистре
    if not any(char.islower() for char in password):
        return False, "Пароль должен содержать хотя бы одну строчную букву"

    # Проверка наличия специальных символов
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
    if not any(char in special_chars for char in password):
        return False, "Пароль должен содержать хотя бы один специальный символ"

    return True, None
