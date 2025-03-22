import logging
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from sqlalchemy import String, ForeignKey, func, TIMESTAMP, JSON, Boolean, Enum as SQLAlchemyEnum
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Mapped, mapped_column

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Получение строки подключения из переменной окружения, если она не задана – используется значение по умолчанию.
DB_HOST = os.getenv("PASS_DB_HOST")
DB_PORT = os.getenv("PASS_DB_PORT")
DB_NAME = os.getenv("PASS_DB_NAME")
DB_USER = os.getenv("PASS_DB_USER")
DB_PASSWORD = os.getenv("PASS_DB_PASSWORD")

DATABASE_URL = f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Создание асинхронного движка
engine = create_async_engine(DATABASE_URL)
SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()


# Перечисление для OAuth провайдеров
class OAuthProvider(str, Enum):
    GOOGLE = "google"
    GITHUB = "github"
    YANDEX = "yandex"
    VK = "vk"


class AdminsBase(Base):
    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(primary_key=True)
    login: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # Nullable для OAuth
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(),
                                                 onupdate=func.now())

    # OAuth поля
    oauth_provider: Mapped[Optional[str]] = mapped_column(SQLAlchemyEnum(OAuthProvider), nullable=True)
    oauth_user_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    last_login: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Связь: один админ может иметь много проектов
    projects: Mapped[List["ProjectsBase"]] = relationship("ProjectsBase", back_populates="owner")

    def __repr__(self):
        return f"<AdminsBase(id={self.id}, email={self.email})>"


class ProjectsBase(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_id: Mapped[int] = mapped_column(ForeignKey("admins.id"), nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    # OAuth настройки для проекта
    oauth_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    oauth_providers: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Добавляем поля created_at и updated_at
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(),
                                                 onupdate=func.now())

    # Связи
    owner: Mapped["AdminsBase"] = relationship("AdminsBase", back_populates="projects")
    users: Mapped[List["UsersBase"]] = relationship("UsersBase", back_populates="project")

    def __repr__(self):
        return f"<ProjectsBase(id={self.id}, name={self.name})>"


class UsersBase(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    login: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # Nullable для OAuth
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="user") #новый столбец роли
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(),
                                                 onupdate=func.now())

    # OAuth поля
    oauth_provider: Mapped[Optional[str]] = mapped_column(SQLAlchemyEnum(OAuthProvider), nullable=True)
    oauth_user_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    last_login: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Связь: пользователь принадлежит одному проекту
    project: Mapped["ProjectsBase"] = relationship("ProjectsBase", back_populates="users")

    def __repr__(self):
        return f"<UsersBase(id={self.id}, email={self.email})>"


class RevokedTokens(Base):
    __tablename__ = "revoked_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    jti: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)


async def init_db():
    """Создает все таблицы в базе данных."""
    try:
        logger.info("Создание таблиц в базе данных...")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Таблицы успешно созданы!")
    except Exception as e:
        logger.error(f"Ошибка при создании таблиц: {e}")


if __name__ == '__main__':
    import asyncio

    asyncio.run(init_db())