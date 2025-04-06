from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_maker
from app.schemas import TokenResponse
from app.jwt_auth import refresh_tokens

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
        refresh_data: dict = None,
        db: AsyncSession = Depends(get_async_session)
):
    """
    Обновление токенов с использованием refresh токена.
    Токен может быть получен из тела запроса, cookie или заголовка.
    """
    # Получаем refresh token из разных источников
    refresh_token = None

    # 1. Из body запроса, если передан
    if refresh_data and "refresh_token" in refresh_data:
        refresh_token = refresh_data["refresh_token"]

    # 2. Из cookie, если не найден в body
    if not refresh_token:
        refresh_token = request.cookies.get("admins_refresh_token") or request.cookies.get("users_refresh_token")

    # 3. Из заголовка Authorization, если не найден в cookie и body
    if not refresh_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            refresh_token = auth_header.replace("Bearer ", "")

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token not provided"
        )

    try:
        # Вызываем функцию обновления токенов
        tokens = await refresh_tokens(refresh_token, db)

        # Устанавливаем новые токены в cookie
        is_admin = "admins_" in request.cookies.get("admins_refresh_token", "") if request.cookies else False

        token_prefix = "admins_" if is_admin else "users_"

        response.set_cookie(
            key=f"{token_prefix}access_token",
            value=tokens["access_token"],
            httponly=True,
            secure=True,
            samesite="strict"
        )

        response.set_cookie(
            key=f"{token_prefix}refresh_token",
            value=tokens["refresh_token"],
            httponly=True,
            secure=True,
            samesite="strict"
        )

        # Возвращаем новые токены в теле ответа
        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="bearer"
        )

    except HTTPException as e:
        # Перебрасываем ошибку дальше
        raise e
    except Exception as e:
        # Логируем неожиданную ошибку
        print(f"Unexpected error during token refresh: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh tokens"
        )
