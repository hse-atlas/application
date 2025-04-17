from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import async_session_maker
from app.schemas import RegisterData, LoginData, TokenResponse, AdminsBase, AdminProfileResponse
from app.security import verify_password, get_password_hash, password_meets_requirements
# Изменено: импортируем get_current_admin отдельно, refresh_tokens больше не нужен здесь
from app.jwt_auth import create_access_token, create_refresh_token, get_current_admin

# Добавим логирование в авторизацию админов
import logging

# Получаем логгер для аутентификации
logger = logging.getLogger('auth') # Используем существующий логгер 'auth'

# Создаем лимитер для защиты от брутфорс-атак
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix='/api/auth/admin', tags=['Admin Auth'])


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Регистрация администратора (без изменений)
@router.post("/register/", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def admin_registration(
        request: Request,
        admin_data: RegisterData,
        db: AsyncSession = Depends(get_async_session)
):
    logger.info(f"Admin registration attempt: email={admin_data.email}, login={admin_data.login}")

    # Проверка email
    from app.core import find_one_or_none_admin
    admin_email = await find_one_or_none_admin(email=admin_data.email)
    if admin_email:
        logger.warning(f"Admin registration failed: email {admin_data.email} already exists")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='E-mail already registered'
        )

    # Проверка логина
    admin_login = await find_one_or_none_admin(login=admin_data.login)
    if admin_login:
        logger.warning(f"Admin registration failed: login {admin_data.login} already exists")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='Login already exists'
        )

    # Проверка сложности пароля
    is_valid, error_message = password_meets_requirements(admin_data.password)
    if not is_valid:
        logger.warning(
            f"Admin registration failed: password for {admin_data.email} doesn't meet requirements. Error: {error_message}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    try:
        # Хеширование пароля и добавление администратора
        admin_dict = admin_data.dict()
        admin_dict['password'] = get_password_hash(admin_data.password)
        logger.debug(f"Password hashed for admin email={admin_data.email}")

        from app.core import add_admin
        new_admin = await add_admin(**admin_dict)
        logger.info(f"Admin registered successfully: id={new_admin.id}, email={admin_data.email}")

        return {'message': 'Registration completed successfully!', 'admin_id': new_admin.id}
    except Exception as e:
        logger.error(f"Error during admin registration for email={admin_data.email}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Registration failed due to server error'
        )


# Авторизация администратора
@router.post("/login/", response_model=TokenResponse)
@limiter.limit("10/minute")
async def admin_auth(
        request: Request,
        response: Response,
        admin_data: LoginData,
        db: AsyncSession = Depends(get_async_session)
):
    logger.info(f"Admin login attempt: email={admin_data.email}")

    # Поиск администратора по email
    from app.core import find_one_or_none_admin
    admin = await find_one_or_none_admin(email=admin_data.email)

    if not admin:
        logger.warning(f"Admin login failed: email {admin_data.email} not found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid email or password'
        )

    # Проверка пароля
    # Добавлено: Убедимся, что у админа есть пароль (не только OAuth)
    if not admin.password:
        logger.warning(f"Admin login failed: account {admin_data.email} uses OAuth, password login disabled.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Password login not available for this account'
        )

    password_valid = verify_password(admin_data.password, admin.password)
    if not password_valid:
        logger.warning(f"Admin login failed: incorrect password for email {admin_data.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid email or password'
        )

    # Генерация токенов
    logger.info(f"Admin login successful: email={admin_data.email}, id={admin.id}")
    logger.debug(f"Generating tokens for admin id={admin.id}")

    try:
        # Изменено: Передаем user_type="admin"
        access_token = await create_access_token({"sub": str(admin.id)}, user_type="admin")
        refresh_token = await create_refresh_token({"sub": str(admin.id)}, user_type="admin")

        logger.debug(f"Tokens generated successfully for admin id={admin.id}")
        logger.debug(f"Access token starts with: {access_token[:10]}...")
        logger.debug(f"Refresh token starts with: {refresh_token[:10]}...")

        # Установка токенов в cookie (httponly для безопасности)
        response.set_cookie(
            key="admins_access_token",
            value=access_token,
            httponly=True,
            secure=True,  # Только через HTTPS в production
            samesite="strict"  # Защита от CSRF
        )
        response.set_cookie(
            key="admins_refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="strict"
        )
        logger.info(f"Cookies set for admin id={admin.id}")

        # Возвращаем токены также в теле ответа (для использования в мобильных приложениях)
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    except Exception as e:
        logger.error(f"Error during token generation for admin id={admin.id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to generate authentication tokens'
        )


# Получение профиля администратора (без изменений)
@router.get("/me", response_model=AdminProfileResponse)
async def get_admin_profile(
        admin: AdminsBase = Depends(get_current_admin)
):
    """
    Получение данных текущего аутентифицированного администратора.
    Требует валидного JWT токена администратора.
    """
    logger.info(f"Admin profile request processing: id={admin.id}, email={admin.email}")

    try:
        response_data = {
            "login": admin.login,
            "email": admin.email,
            "user_role": "admin" # Роль захардкожена как 'admin'
        }
        logger.info(f"Admin profile response prepared: {response_data}")
        return AdminProfileResponse(**response_data) # Используем модель для валидации ответа
    except Exception as e:
        logger.error(f"Error in get_admin_profile for admin id={admin.id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving admin profile"
        )
