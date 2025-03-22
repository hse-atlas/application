from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import async_session_maker
from app.schemas import RegisterData, LoginData, TokenResponse, AdminsBase, AdminProfileResponse
from app.security import verify_password, get_password_hash, password_meets_requirements
from app.jwt_auth import create_access_token, create_refresh_token, get_current_admin

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