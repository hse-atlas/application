from typing import Optional, Tuple

# Изменено: Импортируем только config
from app.config import config
from passlib.hash import argon2

# Изменено: Контекст Argon2 теперь напрямую использует config
argon2_context = argon2.using(
    time_cost=config.ARGON2_TIME_COST,
    memory_cost=config.ARGON2_MEMORY_COST,
    parallelism=config.ARGON2_PARALLELISM,
    hash_len=config.ARGON2_HASH_LEN,
    salt_len=config.ARGON2_SALT_LEN,
)

# Изменено: Удален класс SecurityConfig и его экземпляр security_config
# class SecurityConfig:
#     PASSWORD_PEPPER: str = config.PASSWORD_PEPPER
#     ARGON2_TIME_COST: int = config.ARGON2_TIME_COST
#     # ... и т.д. ...
# security_config = SecurityConfig()


def get_password_hash(password: str) -> str:
    """
    Хеширует пароль с использованием Argon2id и добавлением перца.
    Args:
        password: Пароль в виде строки
    Returns:
        Хеш пароля
    """
    # Изменено: Используем config напрямую для перца
    peppered_password = f"{password}{config.PASSWORD_PEPPER}"
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
    # Изменено: Используем config напрямую для перца
    peppered_password = f"{plain_password}{config.PASSWORD_PEPPER}"
    # Добавлено: Обработка исключений Passlib для большей надежности
    try:
        return argon2_context.verify(peppered_password, hashed_password)
    except Exception as e:
        # Логируем ошибку верификации (может быть полезно при отладке хешей)
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Password verification failed: {e}", exc_info=False) # Не логируем стек по умолчанию
        return False


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