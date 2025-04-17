import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import redis.asyncio as redis
from app.config import get_auth_data, get_redis_url, config
from app.database import async_session_maker
from app.schemas import AdminsBase, UsersBase
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

logger = logging.getLogger(__name__)

# Redis для хранения черного списка токенов и refresh токенов
redis_client = redis.from_url(get_redis_url(), decode_responses=True)

# OAuth2 схема для получения токена из заголовка Authorization
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Конфигурация
ACCESS_TOKEN_EXPIRE_MINUTES = config.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = config.REFRESH_TOKEN_EXPIRE_DAYS
ALGORITHM = config.ALGORITHM
SECRET_KEY = get_auth_data()["secret_key"]

# Новая константа для скользящего окна (процент срока действия токена)
# Если текущее время > (срок истечения - TOKEN_REFRESH_WINDOW_PERCENT), то обновляем токен
TOKEN_REFRESH_WINDOW_PERCENT = 0.7  # 70% от срока действия токена


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Функция для создания access токена
async def create_access_token(data: dict, user_type: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    logger.info(f"Creating access token for user ID: {to_encode.get('sub')}, type: {user_type}")

    # Добавляем тип пользователя в payload токена
    to_encode.update({"user_type": user_type})

    # Добавляем jti (JWT ID) для возможности отзыва токена
    jti = str(uuid.uuid4())
    to_encode.update({"jti": jti})
    logger.info(f"JWT ID (jti): {jti}")

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    expire_str = expire.isoformat()
    logger.info(f"Token expiration: {expire_str}")

    to_encode.update({"exp": expire, "type": "access"})
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.info(f"Access token created: {encoded_jwt[:10]}...")
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error encoding JWT: {str(e)}")
        raise


# Функция для создания refresh токена
async def create_refresh_token(data: dict, user_type: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    logger.info(f"Creating refresh token for user ID: {to_encode.get('sub')}, type: {user_type}")

    # Добавляем тип пользователя в payload токена
    to_encode.update({"user_type": user_type})

    # Добавляем jti (JWT ID) для возможности отзыва токена
    jti = str(uuid.uuid4())
    to_encode.update({"jti": jti})
    logger.info(f"JWT ID (jti): {jti}")

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    expire_str = expire.isoformat()
    logger.info(f"Token expiration: {expire_str}")

    to_encode.update({"exp": expire, "type": "refresh"})
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.info(f"Refresh token created: {encoded_jwt[:10]}...")

        # Сохраняем refresh токен в Redis для проверки валидности
        # и возможности отзыва всех токенов пользователя
        expiry = int(expires_delta.total_seconds()) if expires_delta else REFRESH_TOKEN_EXPIRE_DAYS * 86400
        logger.info(f"Saving refresh token in Redis with key: refresh_token:{jti}, expiry: {expiry}s")
        await redis_client.setex(f"refresh_token:{jti}", expiry, to_encode["sub"])
        logger.info("Refresh token saved in Redis")

        return encoded_jwt
    except Exception as e:
        logger.error(f"Error encoding or storing refresh JWT: {str(e)}")
        raise


# Функция для проверки и декодирования токена
async def decode_token(token: str) -> Dict[str, Any]:
    try:
        # Декодируем без проверки подписи для получения payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_signature": False})

        jti = payload.get("jti")
        exp = payload.get("exp")
        now = datetime.now(timezone.utc).timestamp()

        # Проверяем срок действия токена
        if exp and now > exp:
            logger.info(f"Token {jti} has expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Проверка черного списка
        if jti:
            in_blacklist = await redis_client.exists(f"blacklist:{jti}")
            logger.info(f"Blacklist check - JTI: {jti}, In blacklist: {in_blacklist}")

            if in_blacklist:
                logger.warning(f"Token {jti} found in blacklist")

                # Дополнительная проверка времени жизни токена в черном списке
                blacklist_ttl = await redis_client.ttl(f"blacklist:{jti}")
                logger.info(f"Blacklist TTL for {jti}: {blacklist_ttl}")

                # Если TTL менее 60 секунд, считаем токен устаревшим
                if blacklist_ttl < 60:
                    logger.info(f"Token {jti} blacklist TTL is too short, allowing token")
                    return payload

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        # Полная проверка подписи токена
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload

    except jwt.ExpiredSignatureError:
        logger.warning("Token signature has expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.JWTError as e:
        logger.error(f"JWT validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Функция для отзыва токена (добавление в черный список)
async def revoke_token(token: str, delay_seconds: int = 0):
    """
    Отзыв токена с опциональной задержкой

    Args:
        token: Токен для отзыва
        delay_seconds: Задержка перед добавлением в черный список (по умолчанию 0 - немедленный отзыв)
    """
    try:
        # Декодируем без проверки подписи
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_signature": False})
        jti = payload.get("jti")
        exp = payload.get("exp")
        now = datetime.now(timezone.utc).timestamp()

        # Проверяем, что токен еще не полностью истек
        if not exp or now > exp:
            logger.info(f"Token {jti} already expired, skipping revocation")
            return False

        # Проверяем, не находится ли токен уже в черном списке
        existing_blacklist = await redis_client.exists(f"blacklist:{jti}")
        if existing_blacklist:
            logger.info(f"Token {jti} already in blacklist, skipping")
            return False

        # Стандартное немедленное добавление в черный список
        ttl = max(1, int(exp - now))
        logger.info(f"Revoking token immediately: JTI={jti}, TTL={ttl}")
        await redis_client.setex(f"blacklist:{jti}", ttl, "1")
        return True
    except Exception as e:
        logger.error(f"Error during token revocation: {str(e)}")
        return False


async def delayed_revocation(jti: str, exp: float, delay_seconds: int):
    """
    Отложенное добавление токена в черный список

    Args:
        jti: Уникальный идентификатор токена
        exp: Время истечения токена в Unix timestamp
        delay_seconds: Задержка в секундах
    """
    try:
        # Ждем указанное время
        await asyncio.sleep(delay_seconds)

        # Проверяем снова, не истек ли срок действия
        now = datetime.now(timezone.utc).timestamp()
        if now > exp:
            logger.info(f"Token {jti} expired during delay, skipping revocation")
            return

        # Устанавливаем TTL
        ttl = max(1, int(exp - now))
        logger.info(f"Delayed token revocation: JTI={jti}, TTL={ttl}")
        await redis_client.setex(f"blacklist:{jti}", ttl, "1")
    except Exception as e:
        logger.error(f"Error during delayed token revocation: {str(e)}")


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


# Проверяет, нужно ли обновить токен на основе скользящего окна
async def should_refresh_token(payload) -> bool:
    if payload.get("type") != "access":
        return False

    exp = payload.get("exp")
    if not exp:
        return False

    # Рассчитываем время истечения срока действия
    expiration_time = datetime.fromtimestamp(exp, tz=timezone.utc)
    current_time = datetime.now(timezone.utc)

    # Получаем время создания токена
    issued_at = payload.get("iat")
    if not issued_at:
        issued_at_time = current_time - timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    else:
        issued_at_time = datetime.fromtimestamp(issued_at, tz=timezone.utc)

    # Рассчитываем полную длительность действия токена
    token_lifetime = expiration_time - issued_at_time

    # Рассчитываем порог обновления (70% от времени жизни токена)
    # Обновлять токен, когда осталось меньше 30% времени жизни
    refresh_threshold = expiration_time - (token_lifetime * (1 - TOKEN_REFRESH_WINDOW_PERCENT))

    # Если текущее время после порога обновления, то обновляем токен
    need_refresh = current_time >= refresh_threshold

    logger.info(f"Token refresh check: "
                f"Current time: {current_time}, "
                f"Expiration: {expiration_time}, "
                f"Refresh threshold: {refresh_threshold}, "
                f"Need refresh: {need_refresh}")

    return need_refresh


# Middleware для проверки и обновления токенов
async def auth_middleware(request: Request, db: AsyncSession = Depends(get_async_session)):
    logger.info(f"Auth middleware check for path: {request.url.path}")

    # Получаем токены из cookies или заголовка Authorization
    admin_access_token = request.cookies.get("admins_access_token")
    user_access_token = request.cookies.get("users_access_token")
    access_token = admin_access_token or user_access_token

    logger.info(f"Admin token from cookies: {'Found' if admin_access_token else 'Not found'}")
    logger.info(f"User token from cookies: {'Found' if user_access_token else 'Not found'}")

    # Или в заголовке Authorization
    if not access_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header.replace("Bearer ", "")
            logger.info("Access token found in Authorization header")

    if not access_token:
        logger.info("No access token found in request")
        # Требуем аутентификацию для защищенных маршрутов
        if request.url.path.startswith("/api/protected"):
            logger.warning(f"Protected route {request.url.path} accessed without auth token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return None

    try:
        # Декодируем и проверяем токен
        logger.info("Decoding access token")
        payload = await decode_token(access_token)
        token_type = payload.get("type")
        logger.info(f"Token type: {token_type}")

        # Проверяем, что это access токен
        if token_type != "access":
            logger.warning(f"Expected access token, but got {token_type}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Получаем ID и тип пользователя из токена
        user_id = payload.get("sub")
        user_type = payload.get("user_type")

        if not user_id or not user_type:
            logger.warning(f"Token missing required claims: sub={user_id}, user_type={user_type}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        logger.info(f"User ID from token: {user_id}, Type: {user_type}")

        # Проверяем существование пользователя на основе типа из токена
        if user_type == "admin":
            admin_result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
            admin = admin_result.scalar_one_or_none()

            if not admin:
                logger.warning(f"Admin with ID {user_id} not found in database")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Admin not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            logger.info(f"Admin found: ID={admin.id}, login={admin.login}, email={admin.email}")
            request.state.user = admin
            request.state.user_type = "admin"
            actual_user = admin

        elif user_type == "user":
            user_result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
            user = user_result.scalar_one_or_none()

            if not user:
                logger.warning(f"User with ID {user_id} not found in database")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            logger.info(f"User found: ID={user.id}, login={user.login}, email={user.email}")
            request.state.user = user
            request.state.user_type = "user"
            actual_user = user

        else:
            logger.warning(f"Invalid user type in token: {user_type}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Проверяем, соответствует ли тип токена (из cookie) типу пользователя
        token_from_admin_cookie = access_token == admin_access_token
        cookie_type_mismatch = (token_from_admin_cookie and request.state.user_type != "admin") or \
                               (not token_from_admin_cookie and request.state.user_type == "admin")

        if cookie_type_mismatch:
            logger.warning(
                f"Token cookie type ({token_from_admin_cookie}) doesn't match user type ({request.state.user_type})")

        # Проверяем доступ к защищенным маршрутам
        is_admin_route = any([
            request.url.path.startswith("/api/auth/admin"),  # Маршруты аутентификации админа
            request.url.path.startswith("/api/projects"),  # Маршруты управления проектами
            request.url.path.startswith("/api/users"),  # Маршруты управления пользователями
            request.url.path.startswith("/api/debug/")  # Маршруты отладки
        ])

        if is_admin_route and request.state.user_type != "admin":
            logger.warning(f"Access attempt to admin route {request.url.path} by non-admin user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrator privileges required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        logger.info(f"Auth middleware check completed successfully for {request.state.user_type}")
        return actual_user

    except HTTPException as e:
        logger.warning(f"HTTP exception in auth middleware: {e.detail}")
        raise  # Просто перебрасываем исключение, отдельная логика обновления теперь в специальных эндпоинтах
    except Exception as e:
        logger.error(f"Unexpected error in auth middleware: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error",
            headers={"WWW-Authenticate": "Bearer"},
        )


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

        # Получаем user_id и user_type из токена
        user_id = payload.get("sub")
        user_type = payload.get("user_type")

        if not user_id or not user_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Отзываем использованный refresh токен (one-time use)
        await revoke_token(refresh_token)

        # Создаем новую пару токенов с указанием типа пользователя
        access_token = await create_access_token({"sub": user_id}, user_type=user_type)
        new_refresh_token = await create_refresh_token({"sub": user_id}, user_type=user_type)

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "sub": user_id,
            "user_type": user_type  # Возвращаем тип пользователя
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
    logger.info(f"[DEBUG] get_current_user начал выполнение")
    logger.info(f"[DEBUG] token: {token[:10]}... (первые 10 символов)")

    try:
        payload = await decode_token(token)
        logger.info(f"[DEBUG] token payload: {payload}")

        user_id = payload.get("sub")
        user_type = payload.get("user_type")

        if user_id is None or user_type is None:
            logger.error("[DEBUG] Token не содержит необходимые поля 'sub' или 'user_type'")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        logger.info(f"[DEBUG] ID пользователя: {user_id}, тип: {user_type}")

        # Проверяем пользователя в соответствующей таблице на основе user_type
        if user_type == "admin":
            admin_result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
            admin = admin_result.scalar_one_or_none()

            if not admin:
                logger.error(f"[DEBUG] Администратор с ID {user_id} не найден")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Admin not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            logger.info(f"[DEBUG] Найден администратор: id={admin.id}, email={admin.email}")
            return {"user": admin, "type": "admin"}

        elif user_type == "user":
            user_result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
            user = user_result.scalar_one_or_none()

            if not user:
                logger.error(f"[DEBUG] Пользователь с ID {user_id} не найден")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            logger.info(f"[DEBUG] Найден пользователь: id={user.id}, email={user.email}")
            return {"user": user, "type": "user"}

        else:
            logger.error(f"[DEBUG] Недопустимый тип пользователя в токене: {user_type}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user type",
                headers={"WWW-Authenticate": "Bearer"},
            )

    except JWTError as e:
        logger.error(f"[DEBUG] JWTError в get_current_user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"[DEBUG] Неожиданная ошибка в get_current_user: {str(e)}")
        logger.error(f"[DEBUG] Traceback: ", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving user: {str(e)}",
        )


# Получение только администратора
async def get_current_admin(current_user=Depends(get_current_user)):
    logger.info(f"[DEBUG] get_current_admin начал выполнение")
    logger.info(f"[DEBUG] current_user: {current_user}")

    if not current_user:
        logger.error("[DEBUG] current_user пустой (None)")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    if "type" not in current_user:
        logger.error(f"[DEBUG] current_user не содержит поле 'type': {current_user}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Malformed user data",
        )

    if current_user["type"] != "admin":
        logger.warning(f"[DEBUG] User {current_user.get('user', {}).get('id', 'unknown')} is not an admin")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )

    if "user" not in current_user:
        logger.error(f"[DEBUG] current_user не содержит поле 'user': {current_user}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Malformed user data",
        )

    logger.info(f"[DEBUG] User confirmed as admin: {current_user['user'].id}")
    return current_user["user"]


# Получение только пользователя проекта
async def get_current_project_user(current_user=Depends(get_current_user)):
    if current_user["type"] != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return current_user["user"]
