from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import async_session_maker
from app.schemas import TokenResponse, AdminsBase, UsersBase
from app.jwt_auth import refresh_tokens, decode_token

# Добавляем логирование для common_auth.py
import logging

# Получаем логгер
logger = logging.getLogger('auth')

# Создаем лимитер для защиты от брутфорс-атак
limiter = Limiter(key_func=get_remote_address)

# Создаем новый роутер для общих эндпоинтов аутентификации
router = APIRouter(prefix='/api/auth', tags=['Common Auth'])


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


@router.post("/refresh/", response_model=TokenResponse)
@limiter.limit("20/minute")
async def token_refresh_redirect(
        request: Request,
        response: Response,
        refresh_data: dict = None,
        db: AsyncSession = Depends(get_async_session)
):
    """
    Перенаправление на соответствующий эндпоинт обновления токенов.
    Оставлен для обратной совместимости.
    """
    logger.info("Deprecated token refresh endpoint used")

    # Получаем refresh token из разных источников
    refresh_token = None

    # 1. Из body запроса, если передан
    if refresh_data and "refresh_token" in refresh_data:
        refresh_token = refresh_data["refresh_token"]

    # 2. Из cookie, если не найден в body
    if not refresh_token:
        refresh_token = request.cookies.get("admins_refresh_token") or request.cookies.get("users_refresh_token")

    # 3. Из заголовка Authorization
    if not refresh_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            refresh_token = auth_header.replace("Bearer ", "")

    if not refresh_token:
        logger.warning("Refresh token not provided")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token not provided"
        )

    try:
        # Декодируем токен, чтобы определить тип пользователя
        payload = await decode_token(refresh_token)
        user_id = payload.get("sub")
        user_type = payload.get("user_type")  # Получаем тип пользователя из токена

        if not user_id or not user_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Проверяем тип пользователя из токена
        if user_type == "admin":
            # Перенаправляем на эндпоинт для администраторов
            from app.admin_auth import admin_token_refresh
            return await admin_token_refresh(request, response, refresh_data, db)
        elif user_type == "user":
            # Для пользователей нам понадобится project_id
            # Пробуем найти пользователя
            user_result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
            user = user_result.scalar_one_or_none()

            if user:
                # Перенаправляем на эндпоинт для пользователей
                from app.user_auth import user_token_refresh
                return await user_token_refresh(request, user.project_id, response, refresh_data, db)
            else:
                logger.warning(f"User ID {user_id} not found in database")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        else:
            logger.warning(f"Invalid user type in token: {user_type}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user type",
                headers={"WWW-Authenticate": "Bearer"},
            )

    except HTTPException as e:
        # Перебрасываем ошибку дальше
        logger.error(f"HTTP exception in token refresh redirect: {e.detail}")
        raise e
    except Exception as e:
        # Логируем неожиданную ошибку
        logger.error(f"Unexpected error in token refresh redirect: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to redirect token refresh"
        )