import uuid
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import UUID4

from app.database import Base, int_pk, uuid_pk
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from sqlalchemy import String, ForeignKey, Enum as SQLAlchemyEnum, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship


# Перечисление для OAuth провайдеров
class OAuthProvider(str, Enum):
    GOOGLE = "google"
    GITHUB = "github"
    YANDEX = "yandex"
    VK = "vk"


# ======================== ORM модели ========================

class AdminsBase(Base):
    __tablename__ = "admins"

    id: Mapped[int_pk] = mapped_column(primary_key=True)
    login: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # Nullable для OAuth

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

    id: Mapped[uuid_pk] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_id: Mapped[int] = mapped_column(ForeignKey("admins.id"), nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    # OAuth настройки для проекта
    oauth_enabled: Mapped[bool] = mapped_column(default=False)
    oauth_providers: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)  # JSON с настройками

    # Связи
    owner: Mapped["AdminsBase"] = relationship("AdminsBase", back_populates="projects")
    users: Mapped[List["UsersBase"]] = relationship("UsersBase", back_populates="project")

    def __repr__(self):
        return f"<ProjectsBase(id={self.id}, name={self.name})>"

class UserStatus(str, Enum):
    ACTIVE = "active"
    BLOCKED = "blocked"

class UsersBase(Base):
    __tablename__ = "users"

    id: Mapped[int_pk] = mapped_column(primary_key=True)
    login: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # Nullable для OAuth
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="user")
    status: Mapped[UserStatus] = mapped_column(
        SQLAlchemyEnum(UserStatus),
        nullable=False,
        default=UserStatus.ACTIVE
    )
    # OAuth поля
    oauth_provider: Mapped[Optional[str]] = mapped_column(SQLAlchemyEnum(OAuthProvider), nullable=True)
    oauth_user_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    last_login: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Связь: пользователь принадлежит одному проекту
    project: Mapped["ProjectsBase"] = relationship("ProjectsBase", back_populates="users")

    def __repr__(self):
        return f"<UsersBase(id={self.id}, email={self.email})>"


# Модель для хранения отозванных токенов (если не используем Redis)
class RevokedTokens(Base):
    __tablename__ = "revoked_tokens"

    id: Mapped[int_pk] = mapped_column(primary_key=True)
    jti: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(nullable=False, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)


# ======================== Pydantic-схемы ========================

class RegisterData(BaseModel):
    email: EmailStr = Field(..., description="Email адрес")
    password: str = Field(
        ...,
        min_length=8,
        max_length=50,
        description="Пароль от 8 до 50 символов"
    )
    login: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Логин (от 3 до 50 символов)"
    )

    @field_validator('password')
    def password_complexity(cls, v):
        # Проверка сложности пароля
        if not any(char.isdigit() for char in v):
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        if not any(char.isupper() for char in v):
            raise ValueError('Пароль должен содержать хотя бы одну заглавную букву')
        if not any(char.islower() for char in v):
            raise ValueError('Пароль должен содержать хотя бы одну строчную букву')
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
        if not any(char in special_chars for char in v):
            raise ValueError('Пароль должен содержать хотя бы один специальный символ')
        return v


class LoginData(BaseModel):
    email: EmailStr = Field(..., description="Email адрес")
    password: str = Field(
        ...,
        min_length=5,
        max_length=50,
        description="Пароль от 5 до 50 символов"
    )


class AdminProfileResponse(BaseModel):
    login: str
    email: str
    user_role: str = "admin"

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class OAuthConfig(BaseModel):
    client_id: str
    client_secret: str
    redirect_uri: str
    enabled: bool = True


class ProjectOAuthSettings(BaseModel):
    google: Optional[OAuthConfig] = None
    github: Optional[OAuthConfig] = None
    yandex: Optional[OAuthConfig] = None
    vk: Optional[OAuthConfig] = None
    enabled: bool = False


# ----------------------------------------------------------------------------
# Pydantic-модели (проект)
# ----------------------------------------------------------------------------
class ProjectBase(BaseModel):
    name: str
    description: str
    owner_id: int
    url: Optional[str] = None
    user_count: int
    oauth_enabled: bool = False
    oauth_providers: Optional[ProjectOAuthSettings] = None


class ProjectCreate(BaseModel):
    name: str
    description: str
    url: Optional[str] = None
    oauth_enabled: bool = False
    oauth_providers: Optional[ProjectOAuthSettings] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    oauth_enabled: Optional[bool] = None
    oauth_providers: Optional[ProjectOAuthSettings] = None


class ProjectOut(BaseModel):
    id: UUID
    name: str
    description: str
    owner_id: int
    url: Optional[str] = None
    user_count: Optional[int] = None
    oauth_enabled: bool = False

    model_config = ConfigDict(from_attributes=True)


class ProjectDetailResponse(BaseModel):
    id: UUID
    name: str
    description: str
    owner_id: int
    url: Optional[str] = None
    user_count: int
    users: List[UserResponse]
    oauth_enabled: bool = False
    oauth_providers: Optional[ProjectOAuthSettings] = None

    model_config = ConfigDict(from_attributes=True)


# ----------------------------------------------------------------------------
# Pydantic-модели (пользователь)
# ----------------------------------------------------------------------------
class UserBase(BaseModel):
    login: str
    email: str
    password: Optional[str] = None
    project_id: UUID4
    oauth_provider: Optional[OAuthProvider] = None
    oauth_user_id: Optional[str] = None


class UserCreate(BaseModel):
    login: str
    email: EmailStr
    password: Optional[str] = None
    project_id: UUID4
    oauth_provider: Optional[OAuthProvider] = None
    oauth_user_id: Optional[str] = None

    @field_validator('password')
    def password_or_oauth(cls, v, info):
        # Проверка, что указан либо пароль, либо OAuth провайдер
        if not v and not info.data.get('oauth_provider'):
            raise ValueError('Необходимо указать либо пароль, либо OAuth провайдер')
        if v:
            # Проверка сложности пароля, если он указан
            if not any(char.isdigit() for char in v):
                raise ValueError('Пароль должен содержать хотя бы одну цифру')
            if not any(char.isupper() for char in v):
                raise ValueError('Пароль должен содержать хотя бы одну заглавную букву')
            if not any(char.islower() for char in v):
                raise ValueError('Пароль должен содержать хотя бы одну строчную букву')
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
            if not any(char in special_chars for char in v):
                raise ValueError('Пароль должен содержать хотя бы один специальный символ')
        return v


# Pydantic модель для тела запроса
class UpdateRoleRequest(BaseModel):
    new_role: str


class UserUpdate(BaseModel):
    login: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    status: Optional[UserStatus] = None  # Добавляем поле статуса

class UserOut(BaseModel):
    id: int
    login: str
    email: str
    project_id: UUID4
    role: str
    status: UserStatus
    oauth_provider: Optional[OAuthProvider] = None

    model_config = ConfigDict(from_attributes=True)

class UserResponse(BaseModel):
    id: int
    login: str
    email: str
    role: str
    status: UserStatus
    oauth_provider: Optional[OAuthProvider] = None

    model_config = ConfigDict(from_attributes=True)


class UsersProjectOut(BaseModel):
    project_id: int
    project_name: str
    project_description: str
    users: List[UserOut]

    model_config = ConfigDict(from_attributes=True)
