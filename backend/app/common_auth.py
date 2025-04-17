from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_maker
from app.schemas import TokenResponse
from app.jwt_auth import refresh_tokens # refresh_tokens теперь в jwt_auth

# Добавляем логирование для common_auth.py
import logging

# Получаем логгер
logger = logging.getLogger('auth') # Используем логгер 'auth'

# Создаем лимитер для защиты от брутфорс-атак
limiter = Limiter(key_func=get_remote_address)

# Создаем новый роутер для общих эндпоинтов аутентификации
router = APIRouter(prefix='/api/auth', tags=['Common Auth'])


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


@router.post("/refresh/", response_model=TokenResponse)
@limiter.limit("20/minute")
async def token_refresh(
        request: Request,
        response: Response,
        # Изменено: refresh_data из тела сделаем необязательным, т.к. ищем в cookie/header
        refresh_data: Optional[dict] = None,
        db: AsyncSession = Depends(get_async_session)
):
    """
    Обновление токенов с использованием refresh токена.
    Токен может быть получен из тела запроса (поле 'refresh_token'), cookie или заголовка Authorization.
    """
    logger.info("Token refresh request received")

    # Получаем refresh token из разных источников
    refresh_token = None

    # 1. Из body запроса, если передан
    if refresh_data and isinstance(refresh_data, dict) and "refresh_token" in refresh_data:
        refresh_token = refresh_data["refresh_token"]
        logger.info("Refresh token found in request body")

    # 2. Из cookie, если не найден в body
    if not refresh_token:
        # Ищем сначала админский, потом пользовательский
        refresh_token = request.cookies.get("admins_refresh_token")
        if refresh_token:
             logger.info(f"Refresh token found in 'admins_refresh_token' cookie")
        else:
            refresh_token = request.cookies.get("users_refresh_token")
            if refresh_token:
                logger.info(f"Refresh token found in 'users_refresh_token' cookie")

    # 3. Из заголовка Authorization, если не найден в cookie и body
    if not refresh_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            refresh_token = auth_header.replace("Bearer ", "")
            logger.info("Refresh token found in Authorization header")

    if not refresh_token:
        logger.warning("Refresh token not provided in body, cookies, or header")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token not provided"
        )

    try:
        # Вызываем функцию обновления токенов
        logger.info("Attempting to refresh tokens...")

        # Логируем начало токена для отладки
        token_preview = refresh_token[:10] + "..." if refresh_token else "None"
        logger.debug(f"Using refresh token starting with: {token_preview}")

        # Изменено: Вызываем обновленную функцию refresh_tokens из jwt_auth
        tokens_data = await refresh_tokens(refresh_token, db) # Теперь возвращает и user_type
        logger.info(f"Tokens successfully refreshed for user type: {tokens_data['user_type']}")

        # Изменено: Определяем префикс cookie на основе user_type из ответа refresh_tokens
        token_prefix = "admins_" if tokens_data['user_type'] == "admin" else "users_"
        logger.info(f"Setting cookies with token prefix: {token_prefix}")

        # Устанавливаем новые токены в cookie
        response.set_cookie(
            key=f"{token_prefix}access_token",
            value=tokens_data["access_token"],
            httponly=True,
            secure=True, # Включать в production
            samesite="strict"
        )
        response.set_cookie(
            key=f"{token_prefix}refresh_token",
            value=tokens_data["refresh_token"],
            httponly=True,
            secure=True, # Включать в production
            samesite="strict"
        )
        logger.info("Cookies set with new tokens")

        # Изменено: Возвращаем новые токены в теле ответа (без user_type)
        return TokenResponse(
            access_token=tokens_data["access_token"],
            refresh_token=tokens_data["refresh_token"],
            token_type="bearer"
        )

    except HTTPException as e:
        # Перебрасываем ошибку дальше, логируем детали
        logger.error(f"HTTP exception during token refresh: {e.detail} (Status: {e.status_code})")
        # Если токен невалиден, возможно, стоит удалить cookie
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
             response.delete_cookie("admins_refresh_token")
             response.delete_cookie("users_refresh_token")
             response.delete_cookie("admins_access_token")
             response.delete_cookie("users_access_token")
             logger.info("Cleared potentially invalid auth cookies.")
        raise e
    except Exception as e:
        # Логируем неожиданную ошибку
        logger.error(f"Unexpected error during token refresh: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh tokens due to server error"
        )
