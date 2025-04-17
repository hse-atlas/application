import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import redis.asyncio as redis
from app.config import config, get_auth_data, get_redis_url # Добавлено: импорт config
from app.database import async_session_maker
from app.schemas import AdminsBase, UsersBase, UserStatus # Добавлено: UserStatus
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

# Изменено: Используем общие ALGORITHM и SECRET_KEY из config
ALGORITHM = config.ALGORITHM
SECRET_KEY = get_auth_data()["secret_key"]

# Изменено: Убраны старые константы времени жизни
# ACCESS_TOKEN_EXPIRE_MINUTES = config.ACCESS_TOKEN_EXPIRE_MINUTES
# REFRESH_TOKEN_EXPIRE_DAYS = config.REFRESH_TOKEN_EXPIRE_DAYS

# Новая константа для скользящего окна (процент срока действия токена)
# Можно оставить общей или разделить по типам пользователей, если нужно
TOKEN_REFRESH_WINDOW_PERCENT = 0.7  # 70% от срока действия токена


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Изменено: Функция принимает user_type и использует раздельные настройки времени жизни
async def create_access_token(data: dict, user_type: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    logger.info(f"Creating access token for {user_type} ID: {to_encode.get('sub')}")

    # Добавляем jti (JWT ID) для возможности отзыва токена
    jti = str(uuid.uuid4())
    to_encode.update({"jti": jti})
    logger.info(f"JWT ID (jti): {jti}")

    # Добавлено: Добавляем тип пользователя в payload
    to_encode.update({"usr_type": user_type})

    # Изменено: Определяем время жизни в зависимости от типа пользователя
    if expires_delta is None:
        if user_type == "admin":
            minutes = config.ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES
        elif user_type == "user":
            minutes = config.USER_ACCESS_TOKEN_EXPIRE_MINUTES
        else:
            # По умолчанию или для неизвестного типа - использовать пользовательские настройки
            minutes = config.USER_ACCESS_TOKEN_EXPIRE_MINUTES
            logger.warning(f"Unknown user_type '{user_type}' for token creation, using user expiry.")
        expires_delta = timedelta(minutes=minutes)

    expire = datetime.now(timezone.utc) + expires_delta
    expire_str = expire.isoformat()
    logger.info(f"Token expiration for {user_type}: {expire_str}")

    to_encode.update({"exp": expire, "type": "access"}) # Сохраняем тип "access"
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.info(f"Access token created for {user_type}: {encoded_jwt[:10]}...")
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error encoding JWT for {user_type}: {str(e)}")
        raise


# Изменено: Функция принимает user_type и использует раздельные настройки времени жизни
async def create_refresh_token(data: dict, user_type: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    logger.info(f"Creating refresh token for {user_type} ID: {to_encode.get('sub')}")

    # Добавляем jti (JWT ID) для возможности отзыва токена
    jti = str(uuid.uuid4())
    to_encode.update({"jti": jti})
    logger.info(f"JWT ID (jti): {jti}")

    # Добавлено: Добавляем тип пользователя в payload
    to_encode.update({"usr_type": user_type})

    # Изменено: Определяем время жизни в зависимости от типа пользователя
    expiry_seconds = 0 # Инициализация
    if expires_delta is None:
        if user_type == "admin":
            days = config.ADMIN_REFRESH_TOKEN_EXPIRE_DAYS
            expiry_seconds = days * 86400
        elif user_type == "user":
            days = config.USER_REFRESH_TOKEN_EXPIRE_DAYS
            expiry_seconds = days * 86400
        else:
            days = config.USER_REFRESH_TOKEN_EXPIRE_DAYS
            expiry_seconds = days * 86400
            logger.warning(f"Unknown user_type '{user_type}' for refresh token creation, using user expiry.")
        expires_delta = timedelta(days=days)
    else:
        # Если expires_delta передано явно, вычисляем секунды
        expiry_seconds = int(expires_delta.total_seconds())


    expire = datetime.now(timezone.utc) + expires_delta
    expire_str = expire.isoformat()
    logger.info(f"Refresh token expiration for {user_type}: {expire_str}")

    to_encode.update({"exp": expire, "type": "refresh"}) # Сохраняем тип "refresh"
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.info(f"Refresh token created for {user_type}: {encoded_jwt[:10]}...")

        # Сохраняем refresh токен в Redis для проверки валидности
        # и возможности отзыва всех токенов пользователя
        logger.info(f"Saving refresh token in Redis with key: refresh_token:{jti}, expiry: {expiry_seconds}s")
        # Изменено: Убедимся, что используем правильную переменную expiry_seconds
        await redis_client.setex(f"refresh_token:{jti}", expiry_seconds, to_encode["sub"])
        logger.info("Refresh token saved in Redis")

        return encoded_jwt
    except Exception as e:
        logger.error(f"Error encoding or storing refresh JWT for {user_type}: {str(e)}")
        raise


# Функция для проверки и декодирования токена (без изменений)
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
            logger.debug(f"Blacklist check - JTI: {jti}, In blacklist: {in_blacklist}") # Изменено: Уровень лога на debug

            if in_blacklist:
                logger.warning(f"Token {jti} found in blacklist")

                # Дополнительная проверка времени жизни токена в черном списке (опционально, можно убрать)
                # blacklist_ttl = await redis_client.ttl(f"blacklist:{jti}")
                # logger.info(f"Blacklist TTL for {jti}: {blacklist_ttl}")
                # if blacklist_ttl < 60:
                #     logger.info(f"Token {jti} blacklist TTL is too short, allowing token")
                #     return payload # Убрано - если в черном списке, то отказ

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


# Функция для отзыва токена (добавление в черный список) (без изменений)
async def revoke_token(token: str, delay_seconds: int = 0): # Изменено: дефолтная задержка 0 для logout
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

        if not jti:
             logger.warning("Attempted to revoke token without jti")
             return False

        # Проверяем, что токен еще не полностью истек
        if not exp or now > exp:
            logger.info(f"Token {jti} already expired, skipping revocation")
            return False

        # Проверяем, не находится ли токен уже в черном списке
        existing_blacklist = await redis_client.exists(f"blacklist:{jti}")
        if existing_blacklist:
            logger.info(f"Token {jti} already in blacklist, skipping")
            return False

        # Применяем задержку для добавления в черный список
        if delay_seconds > 0:
            logger.info(f"Scheduling token revocation with {delay_seconds}s delay: JTI={jti}")
            # Используем asyncio.create_task для отложенного выполнения
            asyncio.create_task(delayed_revocation(jti, exp, delay_seconds))
            return True
        else:
            # Стандартное немедленное добавление в черный список
            ttl = max(1, int(exp - now))
            logger.info(f"Revoking token immediately: JTI={jti}, TTL={ttl}")
            await redis_client.setex(f"blacklist:{jti}", ttl, "1")
            return True
    except Exception as e:
        logger.error(f"Error during token revocation: {str(e)}")
        return False


# Функция отложенного добавления в черный список (без изменений)
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


# Функция для отзыва всех токенов пользователя (без изменений)
async def revoke_all_user_tokens(user_id: str):
    # Находим все refresh токены пользователя
    cursor = '0'
    revoked_count = 0
    while True:
        cursor, keys = await redis_client.scan(cursor, match=f"refresh_token:*", count=100)
        logger.debug(f"Scanning Redis for refresh tokens, cursor: {cursor}, found keys: {len(keys)}")
        tasks = []
        for key in keys:
            tasks.append(check_and_revoke_refresh_token(key, user_id))

        results = await asyncio.gather(*tasks)
        revoked_count += sum(1 for r in results if r)

        if cursor == '0' or cursor == 0: # Redis может вернуть 0 или '0'
             logger.info(f"Redis scan finished for user {user_id}.")
             break
    logger.info(f"Finished revoking tokens for user {user_id}. Total revoked: {revoked_count}")
    return True

# Вспомогательная функция для revoke_all_user_tokens
async def check_and_revoke_refresh_token(key: str, target_user_id: str):
    user = await redis_client.get(key)
    if user == target_user_id:
        jti = key.split(":")[-1]
        # Определяем TTL для черного списка (максимальное время жизни refresh токена)
        # Можно использовать любую из констант, т.к. это максимум
        blacklist_ttl = max(config.ADMIN_REFRESH_TOKEN_EXPIRE_DAYS, config.USER_REFRESH_TOKEN_EXPIRE_DAYS) * 86400
        logger.info(f"Revoking refresh token {jti} for user {target_user_id} (from revoke_all)")
        await redis_client.setex(f"blacklist:{jti}", blacklist_ttl, "1")
        await redis_client.delete(key)
        return True
    return False


# Изменено: Функция использует usr_type из payload для определения времени жизни
async def should_refresh_token(payload) -> bool:
    if payload.get("type") != "access":
        return False

    exp = payload.get("exp")
    user_type = payload.get("usr_type") # Получаем тип из токена
    if not exp or not user_type:
        logger.warning("Cannot check token refresh: 'exp' or 'usr_type' missing from payload.")
        return False

    expiration_time = datetime.fromtimestamp(exp, tz=timezone.utc)
    current_time = datetime.now(timezone.utc)

    # Изменено: Получаем время жизни access токена для этого типа пользователя
    if user_type == "admin":
        token_lifetime_minutes = config.ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES
    elif user_type == "user":
        token_lifetime_minutes = config.USER_ACCESS_TOKEN_EXPIRE_MINUTES
    else:
        token_lifetime_minutes = config.USER_ACCESS_TOKEN_EXPIRE_MINUTES # Default
        logger.warning(f"Unknown user_type '{user_type}' in should_refresh_token, using user lifetime.")

    token_lifetime = timedelta(minutes=token_lifetime_minutes)

    # Рассчитываем порог обновления (используем общую константу TOKEN_REFRESH_WINDOW_PERCENT)
    refresh_threshold = expiration_time - (token_lifetime * (1 - TOKEN_REFRESH_WINDOW_PERCENT))

    need_refresh = current_time >= refresh_threshold

    logger.info(f"Token refresh check ({user_type}): "
                f"Current time: {current_time.isoformat()}, "
                f"Expiration: {expiration_time.isoformat()}, "
                f"Refresh threshold: {refresh_threshold.isoformat()}, "
                f"Need refresh: {need_refresh}")

    return need_refresh


# Изменено: Middleware использует usr_type из токена, проверку статуса, передает user_type при создании токенов
async def auth_middleware(request: Request, db: AsyncSession = Depends(get_async_session)):
    logger.info(f"Auth middleware check for path: {request.url.path}")

    # Получаем токены из cookies или заголовка Authorization
    access_token = request.cookies.get("admins_access_token") or request.cookies.get("users_access_token")
    logger.debug(f"Access token from cookies: {'Found' if access_token else 'Not found'}") # Debug level

    # Или в заголовке Authorization
    if not access_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header.replace("Bearer ", "")
            logger.debug("Access token found in Authorization header") # Debug level

    if not access_token:
        logger.info("No access token found in request")
        # Требуем аутентификацию для защищенных маршрутов (пример)
        # if request.url.path.startswith("/api/protected"):
        #     logger.warning(f"Protected route {request.url.path} accessed without auth token")
        #     raise HTTPException(...)
        return None # Для публичных роутов

    try:
        # Декодируем и проверяем токен
        logger.debug("Decoding access token") # Debug level
        payload = await decode_token(access_token)
        token_type = payload.get("type")

        # Изменено: Получаем user_id и user_type из токена
        user_id = payload.get("sub")
        token_user_type = payload.get("usr_type")

        logger.info(f"Token decoded: type={token_type}, user_id={user_id}, user_type={token_user_type}")

        # Проверяем, что это access токен
        if token_type != "access":
            logger.warning(f"Expected access token, but got {token_type}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Изменено: Проверяем наличие user_id и user_type
        if not user_id or not token_user_type:
            logger.warning("Token payload missing 'sub' or 'usr_type' claim")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # --- Изменено: Проверка пользователя в БД на основе token_user_type ---
        user = None
        if token_user_type == "admin":
            logger.debug(f"Looking for admin with ID: {user_id}") # Debug level
            result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
            user = result.scalar_one_or_none()
            if user:
                logger.info(f"Admin found: ID={user.id}")
                request.state.user = user
                request.state.user_type = "admin" # Устанавливаем в state
            else:
                logger.warning(f"Admin with ID {user_id} (from token) not found in database")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin not found")
        elif token_user_type == "user":
            logger.debug(f"Looking for user with ID: {user_id}") # Debug level
            result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
            user = result.scalar_one_or_none()
            if user:
                 # Добавлено: Проверяем статус пользователя из БД
                if user.status == UserStatus.BLOCKED:
                    logger.warning(f"User {user_id} is blocked.")
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is blocked")
                logger.info(f"User found: ID={user.id}")
                request.state.user = user
                request.state.user_type = "user" # Устанавливаем в state
            else:
                logger.warning(f"User with ID {user_id} (from token) not found in database")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        else:
             logger.error(f"Invalid user_type '{token_user_type}' found in token payload")
             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

        # --- СКОЛЬЗЯЩЕЕ ОКНО ---
        is_oauth_redirect = (
                request.url.path == "/" and # Простой пример проверки редиректа
                (request.query_params.get("access_token") or request.query_params.get("refresh_token"))
        )

        # Изменено: Обновляем для любого типа пользователя, если нужно
        if await should_refresh_token(payload) and not is_oauth_redirect:
            logger.info(f"Token requires refresh (sliding window) for {token_user_type}")
            # Изменено: Используем token_user_type при создании новых токенов
            new_access_token = await create_access_token({"sub": user_id}, user_type=token_user_type)
            new_refresh_token = await create_refresh_token({"sub": user_id}, user_type=token_user_type)
            logger.info(f"New tokens created via sliding window: access={new_access_token[:10]}..., refresh={new_refresh_token[:10]}...")

            # Устанавливаем новые токены в request.state, чтобы они были добавлены в ответ
            request.state.new_access_token = new_access_token
            request.state.new_refresh_token = new_refresh_token

            # Отзываем старый access токен с задержкой
            logger.info("Scheduling old access token revocation with delay (sliding window)")
            await revoke_token(access_token, delay_seconds=5)

        logger.info(f"Auth middleware check completed successfully for {token_user_type}")
        return user

    except HTTPException as e:
        # --- Обработка ошибки и проверка Refresh Token ---
        logger.warning(f"HTTP exception in auth middleware: {e.detail} ({e.status_code})")

        # Только если ошибка была 401 или 403 (истек, отозван, заблокирован), пытаемся обновить
        if e.status_code not in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]:
             raise e # Перебрасываем другие ошибки (напр. 404 Not Found)

        refresh_token = request.cookies.get("admins_refresh_token") or request.cookies.get("users_refresh_token")
        logger.debug(f"Refresh token from cookies (after exception): {'Found' if refresh_token else 'Not found'}") # Debug

        if not refresh_token:
            # Если access токен был невалиден и нет refresh токена, то это конец
            logger.warning("No refresh token found to attempt renewal.")
            raise HTTPException(
                 status_code=e.status_code, # Используем исходный статус ошибки
                 detail=e.detail, # Используем исходную деталь ошибки
                 headers={"WWW-Authenticate": "Bearer"},
            ) from e # Сохраняем исходное исключение

        try:
            # Декодируем и проверяем refresh токен
            logger.info("Attempting to use refresh token")
            refresh_payload = await decode_token(refresh_token)

            # Проверяем, что это refresh токен
            if refresh_payload.get("type") != "refresh":
                logger.warning(f"Expected refresh token, but got {refresh_payload.get('type')}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token type")

            # Получаем jti, user_id, user_type из refresh токена
            jti = refresh_payload.get("jti")
            user_id = refresh_payload.get("sub")
            refresh_user_type = refresh_payload.get("usr_type")

            logger.info(f"Refresh token decoded: jti={jti}, user_id={user_id}, user_type={refresh_user_type}")

            # Проверяем наличие jti в Redis
            if not jti or not await redis_client.exists(f"refresh_token:{jti}"):
                logger.warning(f"Invalid or revoked refresh token JTI: {jti}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked refresh token")

            # Проверяем user_id и user_type
            if not user_id or not refresh_user_type:
                logger.warning("Refresh token missing 'sub' or 'usr_type' claim")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token payload")

            # --- Отзываем использованный refresh токен (one-time use) ---
            logger.info(f"Revoking used refresh token {jti}")
            # Добавляем в черный список
            exp = refresh_payload.get("exp", datetime.now(timezone.utc).timestamp() + 1)
            ttl = max(1, int(exp - datetime.now(timezone.utc).timestamp()))
            await redis_client.setex(f"blacklist:{jti}", ttl, "1")
            # Удаляем из списка активных
            await redis_client.delete(f"refresh_token:{jti}")

            # --- Создаем новую пару токенов, используя refresh_user_type ---
            logger.info(f"Creating new tokens using refresh token for {refresh_user_type}")
            new_access_token = await create_access_token({"sub": user_id}, user_type=refresh_user_type)
            new_refresh_token = await create_refresh_token({"sub": user_id}, user_type=refresh_user_type)
            logger.info(f"New tokens created via refresh: access={new_access_token[:10]}..., refresh={new_refresh_token[:10]}...")

            # Устанавливаем новые токены в ответе
            request.state.new_access_token = new_access_token
            request.state.new_refresh_token = new_refresh_token

            # --- Загружаем пользователя из БД (важно для установки user в state) ---
            user = None
            if refresh_user_type == "admin":
                logger.debug(f"Looking for admin with ID: {user_id} (after refresh)")
                result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
                user = result.scalar_one_or_none()
                if user: request.state.user_type = "admin"
            elif refresh_user_type == "user":
                logger.debug(f"Looking for user with ID: {user_id} (after refresh)")
                result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
                user = result.scalar_one_or_none()
                if user:
                    if user.status == UserStatus.BLOCKED: # Повторная проверка статуса
                        logger.warning(f"User {user_id} is blocked (checked after refresh).")
                        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is blocked")
                    request.state.user_type = "user"
            else:
                 logger.error(f"Invalid user_type '{refresh_user_type}' found in refresh token payload")
                 raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token payload")

            if not user:
                 logger.warning(f"User with ID {user_id} and type '{refresh_user_type}' not found after refresh.")
                 raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

            # Добавляем информацию о пользователе в request.state
            request.state.user = user
            logger.info(f"Token refresh completed successfully for {refresh_user_type}")
            return user # Возвращаем пользователя, чтобы запрос продолжился с новой аутентификацией

        except (HTTPException, JWTError) as refresh_exc:
            # Если refresh токен недействителен, требуем повторную аутентификацию
            logger.error(f"Error during refresh token handling: {str(refresh_exc)}")
            # Удаляем невалидные cookie, если они есть
            response = Response(status_code=status.HTTP_401_UNAUTHORIZED)
            response.delete_cookie("admins_access_token")
            response.delete_cookie("admins_refresh_token")
            response.delete_cookie("users_access_token")
            response.delete_cookie("users_refresh_token")
            # Вызываем исключение
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid. Please login again.", # Более общее сообщение
                headers={"WWW-Authenticate": "Bearer"},
            ) from refresh_exc


# Изменено: Функция обновления использует usr_type из токена и возвращает его
async def refresh_tokens(refresh_token: str, db: AsyncSession = Depends(get_async_session)) -> Dict[str, Any]:
    """
    Обновляет токены, используя refresh токен.

    Returns:
        Словарь с новыми access_token, refresh_token, token_type, sub и user_type.
    """
    try:
        # Декодируем и проверяем refresh токен
        payload = await decode_token(refresh_token)

        # Проверяем, что это refresh токен
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type (expected refresh)",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Получаем jti, user_id, user_type для проверки
        jti = payload.get("jti")
        user_id = payload.get("sub")
        user_type = payload.get("usr_type") # Получаем тип из токена

        logger.info(f"Attempting token refresh for user_id={user_id}, user_type={user_type}, jti={jti}")

        # Проверяем наличие jti в Redis
        if not jti or not await redis_client.exists(f"refresh_token:{jti}"):
            logger.warning(f"Invalid or revoked refresh token JTI: {jti}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Проверяем user_id и user_type
        if not user_id or not user_type:
            logger.warning("Refresh token missing 'sub' or 'usr_type' claim")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Дополнительная проверка пользователя в БД (опционально, но рекомендуется)
        user = None
        if user_type == "admin":
            result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
            user = result.scalar_one_or_none()
        elif user_type == "user":
            result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
            user = result.scalar_one_or_none()
            if user and user.status == UserStatus.BLOCKED:
                 logger.warning(f"User {user_id} is blocked. Refresh denied.")
                 raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is blocked")
        if not user:
             logger.warning(f"User {user_id} (type {user_type}) not found in DB during refresh.")
             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")


        # --- Отзываем использованный refresh токен (one-time use) ---
        logger.info(f"Revoking used refresh token {jti} for {user_type} ID {user_id}")
        exp = payload.get("exp", datetime.now(timezone.utc).timestamp() + 1)
        ttl = max(1, int(exp - datetime.now(timezone.utc).timestamp()))
        await redis_client.setex(f"blacklist:{jti}", ttl, "1")
        await redis_client.delete(f"refresh_token:{jti}")

        # --- Создаем новую пару токенов, используя user_type ---
        logger.info(f"Creating new tokens via refresh for {user_type} ID {user_id}")
        new_access_token = await create_access_token({"sub": user_id}, user_type=user_type)
        new_refresh_token = await create_refresh_token({"sub": user_id}, user_type=user_type)

        # Изменено: Возвращаем user_type
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "sub": user_id,
            "user_type": user_type
        }

    except JWTError as e:
        logger.error(f"JWTError during token refresh: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate refresh token credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    except HTTPException as e:
        # Перебрасываем HTTP исключения (например, от проверки статуса)
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during refresh_tokens function: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token refresh failed")


# Изменено: Dependency использует usr_type из токена для оптимизации и проверяет статус
async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: AsyncSession = Depends(get_async_session)
) -> Dict[str, Any]:
    logger.debug(f"[DEBUG] get_current_user started") # Debug level
    try:
        payload = await decode_token(token)
        logger.debug(f"[DEBUG] token payload: {payload}") # Debug level

        user_id = payload.get("sub")
        user_type = payload.get("usr_type") # Изменено: Получаем тип из токена

        if user_id is None or user_type is None:
            logger.error("[DEBUG] Token is missing 'sub' or 'usr_type' field")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials (missing claims)",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Изменено: Проверяем тип из токена и ищем в соответствующей таблице
        if user_type == "admin":
            logger.debug(f"[DEBUG] Looking for admin with ID: {user_id} (type from token)")
            admin_result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
            admin = admin_result.scalar_one_or_none()
            if admin:
                logger.info(f"[DEBUG] Found admin: id={admin.id}")
                return {"user": admin, "type": "admin"}
        elif user_type == "user":
            logger.debug(f"[DEBUG] Looking for user with ID: {user_id} (type from token)")
            user_result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
            user = user_result.scalar_one_or_none()
            if user:
                # Добавлено: Проверка статуса пользователя
                if user.status == UserStatus.BLOCKED:
                    logger.warning(f"[DEBUG] User {user_id} is blocked.")
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is blocked")
                logger.info(f"[DEBUG] Found user: id={user.id}")
                return {"user": user, "type": "user"}
        else:
             logger.error(f"[DEBUG] Unknown user_type '{user_type}' in token")
             raise HTTPException(
                 status_code=status.HTTP_401_UNAUTHORIZED,
                 detail="Invalid user type in token",
                 headers={"WWW-Authenticate": "Bearer"},
             )

        # Если пользователь не найден в ожидаемой таблице (по типу из токена) - это ошибка
        logger.error(f"[DEBUG] User with ID {user_id} and type '{user_type}' not found in DB")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except JWTError as e:
        logger.error(f"[DEBUG] JWTError in get_current_user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials (JWTError)",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    except HTTPException as e: # Перехватываем HTTPException (например, от блокировки)
        logger.warning(f"[DEBUG] HTTPException in get_current_user: {e.detail} ({e.status_code})")
        raise e # Перебрасываем дальше
    except Exception as e:
        logger.error(f"[DEBUG] Unexpected error in get_current_user: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving user: {str(e)}",
        )


# Получение только администратора (без изменений, т.к. работает поверх get_current_user)
async def get_current_admin(current_user: Dict[str, Any] = Depends(get_current_user)):
    logger.debug(f"[DEBUG] get_current_admin started") # Debug level
    # logger.info(f"[DEBUG] current_user: {current_user}") # Слишком многословно для логов

    if not current_user:
        # Эта ветка маловероятна, т.к. get_current_user выбросит исключение раньше
        logger.error("[DEBUG] current_user is empty (None) in get_current_admin")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    if current_user.get("type") != "admin":
        user_id = current_user.get("user", {}).get("id", "unknown")
        logger.warning(f"[DEBUG] User {user_id} is not an admin (type: {current_user.get('type')})")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions (admin required)",
        )

    admin_user = current_user.get("user")
    if not isinstance(admin_user, AdminsBase): # Проверка типа объекта
         logger.error(f"[DEBUG] Malformed user data in get_current_admin: 'user' field is not AdminsBase")
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Malformed user data")

    logger.info(f"[DEBUG] User confirmed as admin: {admin_user.id}")
    return admin_user


# Получение только пользователя проекта (без изменений, т.к. работает поверх get_current_user)
async def get_current_project_user(current_user: Dict[str, Any] = Depends(get_current_user)):
    logger.debug(f"[DEBUG] get_current_project_user started") # Debug level

    if not current_user:
        # Маловероятно
        logger.error("[DEBUG] current_user is empty (None) in get_current_project_user")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    if current_user.get("type") != "user":
        user_id = current_user.get("user", {}).get("id", "unknown")
        logger.warning(f"[DEBUG] User {user_id} is not a project user (type: {current_user.get('type')})")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions (project user required)",
        )

    project_user = current_user.get("user")
    if not isinstance(project_user, UsersBase): # Проверка типа объекта
         logger.error(f"[DEBUG] Malformed user data in get_current_project_user: 'user' field is not UsersBase")
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Malformed user data")

    logger.info(f"[DEBUG] User confirmed as project user: {project_user.id}")
    return project_user
