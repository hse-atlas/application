import os
from pathlib import Path
from typing import List
import secrets

from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    # Общие настройки приложения
    APP_NAME: str = "Atlas Auth Service"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # Настройки базы данных
    PASS_DB_HOST: str
    PASS_DB_PORT: int
    PASS_DB_NAME: str
    PASS_DB_USER: str
    PASS_DB_PASSWORD: str

    # Настройки безопасности
    SECRET_KEY: str
    ALGORITHM: str = "HS256"

    # Новые настройки безопасности
    PASSWORD_PEPPER: str = os.getenv("PASSWORD_PEPPER", secrets.token_hex(16))
    SESSION_SECRET_KEY: str = os.getenv("SESSION_SECRET_KEY", secrets.token_hex(32))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))

    # Параметры для Argon2
    ARGON2_TIME_COST: int = int(os.getenv("ARGON2_TIME_COST", "2"))
    ARGON2_MEMORY_COST: int = int(os.getenv("ARGON2_MEMORY_COST", "102400"))  # 100 МБ
    ARGON2_PARALLELISM: int = int(os.getenv("ARGON2_PARALLELISM", "8"))
    ARGON2_HASH_LEN: int = int(os.getenv("ARGON2_HASH_LEN", "32"))
    ARGON2_SALT_LEN: int = int(os.getenv("ARGON2_SALT_LEN", "16"))

    # Настройки Redis для хранения черного списка токенов
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "")
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))

    # CORS настройки
    CORS_ORIGINS: List[str] = os.getenv("CORS_ORIGINS", "*").split(",")

    # OAuth настройки
    OAUTH_GOOGLE_CLIENT_ID: str = os.getenv("OAUTH_GOOGLE_CLIENT_ID", "")
    OAUTH_GOOGLE_CLIENT_SECRET: str = os.getenv("OAUTH_GOOGLE_CLIENT_SECRET", "")

    OAUTH_GITHUB_CLIENT_ID: str = os.getenv("OAUTH_GITHUB_CLIENT_ID", "")
    OAUTH_GITHUB_CLIENT_SECRET: str = os.getenv("OAUTH_GITHUB_CLIENT_SECRET", "")

    OAUTH_YANDEX_CLIENT_ID: str = os.getenv("OAUTH_YANDEX_CLIENT_ID", "")
    OAUTH_YANDEX_CLIENT_SECRET: str = os.getenv("OAUTH_YANDEX_CLIENT_SECRET", "")

    OAUTH_VK_CLIENT_ID: str = os.getenv("OAUTH_VK_CLIENT_ID", "")
    OAUTH_VK_CLIENT_SECRET: str = os.getenv("OAUTH_VK_CLIENT_SECRET", "")

    BASE_URL: str = os.getenv("BASE_URL", "http://localhost:8000")

    # Настройки для загрузки из .env файла
    model_config = SettingsConfigDict(
        env_file=Path(__file__).absolute().parent.joinpath(".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


# Создаем экземпляр конфигурации
config = Config()


def get_pass_db_url():
    """Получение URL для подключения к базе данных."""
    return (f"postgresql+asyncpg://{config.PASS_DB_USER}:{config.PASS_DB_PASSWORD}@"
            f"{config.PASS_DB_HOST}:{config.PASS_DB_PORT}/{config.PASS_DB_NAME}")


def get_auth_data():
    """Получение данных для аутентификации."""
    return {"secret_key": config.SECRET_KEY, "algorithm": config.ALGORITHM}


def get_redis_url():
    """Получение URL для подключения к Redis."""
    return f"redis://{':' + config.REDIS_PASSWORD + '@' if config.REDIS_PASSWORD else ''}{config.REDIS_HOST}:{config.REDIS_PORT}/{config.REDIS_DB}"


def get_oauth_config():
    """Получение конфигурации OAuth провайдеров."""
    return {
        "google": {
            "client_id": config.OAUTH_GOOGLE_CLIENT_ID,
            "client_secret": config.OAUTH_GOOGLE_CLIENT_SECRET,
            "authorize_url": "https://accounts.google.com/o/oauth2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
            "scope": "email profile",
            "redirect_uri": f"{config.BASE_URL}/api/v1/AuthService/oauth/google/callback"
        },
        "github": {
            "client_id": config.OAUTH_GITHUB_CLIENT_ID,
            "client_secret": config.OAUTH_GITHUB_CLIENT_SECRET,
            "authorize_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
            "scope": "read:user user:email",
            "redirect_uri": f"{config.BASE_URL}/api/v1/AuthService/oauth/github/callback"
        },
        "yandex": {
            "client_id": config.OAUTH_YANDEX_CLIENT_ID,
            "client_secret": config.OAUTH_YANDEX_CLIENT_SECRET,
            "authorize_url": "https://oauth.yandex.ru/authorize",
            "token_url": "https://oauth.yandex.ru/token",
            "userinfo_url": "https://login.yandex.ru/info",
            "scope": "login:email login:info",
            "redirect_uri": f"{config.BASE_URL}/api/v1/AuthService/oauth/yandex/callback"
        },
        "vk": {
            "client_id": config.OAUTH_VK_CLIENT_ID,
            "client_secret": config.OAUTH_VK_CLIENT_SECRET,
            "authorize_url": "https://oauth.vk.com/authorize",
            "token_url": "https://oauth.vk.com/access_token",
            "userinfo_url": "https://api.vk.com/method/users.get",
            "scope": "email",
            "redirect_uri": f"{config.BASE_URL}/api/v1/AuthService/oauth/vk/callback",
            "v": "5.131"  # Версия API VK
        }
    }