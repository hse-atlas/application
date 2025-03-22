from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Dict, Any
import uuid
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import async_session_maker
from app.schemas import AdminsBase, UsersBase
from app.config import get_auth_data, get_redis_url, config

# Redis для хранения черного списка токенов и refresh токенов
redis_client = redis.from_url(get_redis_url(), decode_responses=True)

# OAuth2 схема для получения токена из заголовка Authorization
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Конфигурация
ACCESS_TOKEN_EXPIRE_MINUTES = config.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = config.REFRESH_TOKEN_EXPIRE_DAYS
ALGORITHM = config.ALGORITHM
SECRET_KEY = get_auth_data()["secret_key"]


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Функция для создания access токена
async def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()

    # Добавляем jti (JWT ID) для возможности отзыва токена
    to_encode.update({"jti": str(uuid.uuid4())})

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Функция для создания refresh токена
async def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()

    # Добавляем jti (JWT ID) для возможности отзыва токена
    jti = str(uuid.uuid4())
    to_encode.update({"jti": jti})

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    # Сохраняем refresh токен в Redis для проверки валидности
    # и возможности отзыва всех токенов пользователя
    expiry = int(expires_delta.total_seconds()) if expires_delta else REFRESH_TOKEN_EXPIRE_DAYS * 86400
    await redis_client.setex(f"refresh_token:{jti}", expiry, to_encode["sub"])

    return encoded_jwt


# Функция для проверки и декодирования токена
async def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Проверяем, что токен не в черном списке
        jti = payload.get("jti")
        if jti and await redis_client.exists(f"blacklist:{jti}"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Функция для отзыва токена (добавление в черный список)
async def revoke_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if not jti:
            return False

        # Определяем время жизни токена для установки ttl в Redis
        # Это оптимизирует размер черного списка - токены удаляются
        # автоматически после истечения срока
        exp = payload.get("exp")
        now = datetime.now(timezone.utc).timestamp()
        ttl = max(1, int(exp - now)) if exp else 3600  # Минимум 1 секунда или час по умолчанию

        # Добавляем токен в черный список
        await redis_client.setex(f"blacklist:{jti}", ttl, "1")

        # Для refresh токенов - удаляем их из списка активных
        if payload.get("type") == "refresh":
            await redis_client.delete(f"refresh_token:{jti}")

        return True
    except JWTError:
        return False


# Функция для отзыва всех токенов пользователя
async def revoke_all_user_tokens(user_id: str):
    # Находим все refresh токены пользователя
    cursor = 0
    while True:
        cursor, keys = await redis_client.scan(cursor, match=f"refresh_token:*", count=100)
        for key in keys:
            user = await redis_client.get(key)
            if user == user_id:
                jti = key.split(":")[-1]
                # Добавляем токен в черный список с долгим сроком жизни
                await redis_client.setex(f"blacklist:{jti}", REFRESH_TOKEN_EXPIRE_DAYS * 86400, "1")
                # Удаляем из списка активных
                await redis_client.delete(key)

        if cursor == 0:
            break

    return True


# Middleware для проверки и обновления токенов
async def auth_middleware(request: Request, db: AsyncSession = Depends(get_async_session)):
    # Эта функция предполагается для использования как middleware в FastAPI

    # Проверяем наличие access токена в куках
    access_token = request.cookies.get("admins_access_token") or request.cookies.get("users_access_token")

    # Или в заголовке Authorization
    if not access_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header.replace("Bearer ", "")

    if not access_token:
        # Требуем аутентификацию для защищенных маршрутов
        if request.url.path.startswith("/api/protected"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return None

    try:
        # Декодируем и проверяем токен
        payload = await decode_token(access_token)
        token_type = payload.get("type")

        # Проверяем, что это access токен
        if token_type != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Получаем пользователя из БД
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Определяем тип пользователя (admin или user)
        is_admin_route = request.url.path.startswith("/api/v1/AuthService/admin") or request.url.path.startswith(
            "/projects/owner")

        if is_admin_route:
            result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
            user = result.scalar_one_or_none()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Admin not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            # Добавляем информацию о пользователе в request.state
            request.state.user = user
            request.state.user_type = "admin"
        else:
            result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
            user = result.scalar_one_or_none()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            # Добавляем информацию о пользователе в request.state
            request.state.user = user
            request.state.user_type = "user"

        return user

    except HTTPException:
        # Проверяем refresh токен
        refresh_token = request.cookies.get("admins_refresh_token") or request.cookies.get("users_refresh_token")
        if not refresh_token:
            # Если нет refresh токена, возвращаем исходную ошибку
            if request.url.path.startswith("/api/protected"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None

        try:
            # Декодируем и проверяем refresh токен
            refresh_payload = await decode_token(refresh_token)

            # Проверяем, что это refresh токен
            if refresh_payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Получаем jti для проверки в Redis
            jti = refresh_payload.get("jti")
            if not jti or not await redis_client.exists(f"refresh_token:{jti}"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Получаем user_id из токена
            user_id = refresh_payload.get("sub")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Отзываем использованный refresh токен (one-time use)
            await revoke_token(refresh_token)

            # Создаем новую пару токенов
            new_access_token = await create_access_token({"sub": user_id})
            new_refresh_token = await create_refresh_token({"sub": user_id})

            # Устанавливаем новые токены в ответе
            # Это нужно будет добавить в middleware
            request.state.new_access_token = new_access_token
            request.state.new_refresh_token = new_refresh_token

            # Определяем тип пользователя
            is_admin_route = request.url.path.startswith("/api/v1/AuthService/admin")

            if is_admin_route:
                result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
                user = result.scalar_one_or_none()
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Admin not found",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                # Добавляем информацию о пользователе в request.state
                request.state.user = user
                request.state.user_type = "admin"
            else:
                result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
                user = result.scalar_one_or_none()
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="User not found",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                # Добавляем информацию о пользователе в request.state
                request.state.user = user
                request.state.user_type = "user"

            return user

        except (HTTPException, JWTError):
            # Если refresh токен недействителен, требуем повторную аутентификацию
            if request.url.path.startswith("/api/protected"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token. Please login again.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None


# Функция для обновления токенов с использованием refresh токена
async def refresh_tokens(refresh_token: str, db: AsyncSession = Depends(get_async_session)):
    try:
        # Декодируем и проверяем refresh токен
        payload = await decode_token(refresh_token)

        # Проверяем, что это refresh токен
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Получаем jti для проверки в Redis
        jti = payload.get("jti")
        if not jti or not await redis_client.exists(f"refresh_token:{jti}"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Получаем user_id из токена
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Отзываем использованный refresh токен (one-time use)
        await revoke_token(refresh_token)

        # Создаем новую пару токенов
        access_token = await create_access_token({"sub": user_id})
        new_refresh_token = await create_refresh_token({"sub": user_id})

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "sub": user_id,
        }

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Dependency для получения текущего пользователя (admin или user)
async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: AsyncSession = Depends(get_async_session)
):
    try:
        payload = await decode_token(token)

        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Проверяем, является ли пользователь администратором
        admin_result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
        admin = admin_result.scalar_one_or_none()

        if admin:
            return {"user": admin, "type": "admin"}

        # Если не администратор, проверяем обычного пользователя
        user_result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
        user = user_result.scalar_one_or_none()

        if user:
            return {"user": user, "type": "user"}

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Получение только администратора
async def get_current_admin(current_user=Depends(get_current_user)):
    if current_user["type"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return current_user["user"]


# Получение только пользователя проекта
async def get_current_project_user(current_user=Depends(get_current_user)):
    if current_user["type"] != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return current_user["user"]