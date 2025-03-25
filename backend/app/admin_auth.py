from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import async_session_maker
from app.schemas import RegisterData, LoginData, TokenResponse, AdminsBase, AdminProfileResponse
from app.security import verify_password, get_password_hash, password_meets_requirements
from app.jwt_auth import create_access_token, create_refresh_token, get_current_admin, refresh_tokens

# Создаем лимитер для защиты от брутфорс-атак
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix='/api/v1/AuthService', tags=['Auth API'])


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Регистрация администратора
@router.post("/register/", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")  # Ограничение на 5 запросов в минуту с одного IP
async def admin_registration(
        request: Request,
        admin_data: RegisterData,
        db: AsyncSession = Depends(get_async_session)
):
    # Проверка email
    from app.core import find_one_or_none_admin
    admin_email = await find_one_or_none_admin(email=admin_data.email)
    if admin_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='E-mail already registered'
        )

    # Проверка логина
    admin_login = await find_one_or_none_admin(login=admin_data.login)
    if admin_login:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='Login already exists'
        )

    # Проверка сложности пароля
    is_valid, error_message = password_meets_requirements(admin_data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    # Хеширование пароля и добавление администратора
    admin_dict = admin_data.dict()
    admin_dict['password'] = get_password_hash(admin_data.password)

    from app.core import add_admin
    new_admin = await add_admin(**admin_dict)

    return {'message': 'Registration completed successfully!', 'admin_id': new_admin.id}


# Авторизация администратора
@router.post("/login/", response_model=TokenResponse)
@limiter.limit("10/minute")  # Ограничение на 10 запросов в минуту с одного IP
async def admin_auth(
        request: Request,  # Добавляем обязательный аргумент request
        response: Response,
        admin_data: LoginData,
        db: AsyncSession = Depends(get_async_session)
):
    # Поиск администратора по email
    from app.core import find_one_or_none_admin
    admin = await find_one_or_none_admin(email=admin_data.email)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid email or password'
        )

    # Проверка пароля
    if not verify_password(admin_data.password, admin.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid email or password'
        )

    # Генерация токенов
    access_token = await create_access_token({"sub": str(admin.id)})
    refresh_token = await create_refresh_token({"sub": str(admin.id)})

    # Установка токенов в cookie (httponly для безопасности)
    response.set_cookie(
        key="admins_access_token",
        value=access_token,
        httponly=True,
        secure=True,  # Только через HTTPS
        samesite="strict"  # Защита от CSRF
    )

    response.set_cookie(
        key="admins_refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )

    # Возвращаем токены также в теле ответа (для использования в мобильных приложениях)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post("/refresh/", response_model=TokenResponse)
@limiter.limit("20/minute")  # Ограничение на количество обновлений токенов
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


@router.get("/me", response_model=AdminProfileResponse)
async def get_admin_profile(
        admin: AdminsBase = Depends(get_current_admin)
):
    """
    Получение данных администратора
    Требует валидного JWT токена администратора
    """
    return {
        "login": admin.login,
        "email": admin.email,
        "user_role": "admin"
    }