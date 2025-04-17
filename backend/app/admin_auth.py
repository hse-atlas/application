from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import async_session_maker
from app.schemas import RegisterData, LoginData, TokenResponse, AdminsBase, AdminProfileResponse
from app.security import verify_password, get_password_hash, password_meets_requirements
from app.jwt_auth import create_access_token, create_refresh_token, get_current_admin, refresh_tokens, decode_token, revoke_token

# Добавим логирование в авторизацию админов
import logging

# Получаем логгер для аутентификации
logger = logging.getLogger('auth')

# Создаем лимитер для защиты от брутфорс-атак
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix='/api/auth/admin', tags=['Admin Auth'])


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
        logger.error(f"Error during admin registration for email={admin_data.email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Registration failed due to server error'
        )


# Авторизация администратора
@router.post("/login/", response_model=TokenResponse)
@limiter.limit("10/minute")  # Ограничение на 10 запросов в минуту с одного IP
async def admin_auth(
        request: Request,  # Добавляем обязательный аргумент request
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
        # Обновлено: передаем user_type="admin" в функции создания токенов
        access_token = await create_access_token({"sub": str(admin.id)}, user_type="admin")
        refresh_token = await create_refresh_token({"sub": str(admin.id)}, user_type="admin")

        logger.debug(f"Tokens generated successfully for admin id={admin.id}")
        logger.debug(f"Access token starts with: {access_token[:10]}...")
        logger.debug(f"Refresh token starts with: {refresh_token[:10]}...")

        # Больше не устанавливаем токены в cookie
        logger.info(f"Tokens generated for admin id={admin.id}")

        # Возвращаем токены только в теле ответа
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    except Exception as e:
        logger.error(f"Error during token generation for admin id={admin.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to generate authentication tokens'
        )


@router.get("/me", response_model=AdminProfileResponse)
async def get_admin_profile(
        admin: AdminsBase = Depends(get_current_admin)
):
    """
    Получение данных администратора
    Требует валидного JWT токена администратора
    """
    logger.info(f"Admin profile request processing: id={admin.id}, email={admin.email}")

    try:
        response_data = {
            "login": admin.login,
            "email": admin.email,
            "user_role": "admin"
        }
        logger.info(f"Admin profile response prepared: {response_data}")
        return response_data
    except Exception as e:
        logger.error(f"Error in get_admin_profile: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving admin profile"
        )


@router.post("/refresh/", response_model=TokenResponse)
@limiter.limit("20/minute")
async def admin_token_refresh(
        request: Request,
        refresh_data: dict = None,
        db: AsyncSession = Depends(get_async_session)
):
    """
    Обновление токенов администратора с использованием refresh токена.
    """
    logger.info("Admin token refresh request received")

    # Получаем refresh token только из тела запроса или заголовка
    refresh_token = None

    # 1. Из body запроса, если передан
    if refresh_data and "refresh_token" in refresh_data:
        refresh_token = refresh_data["refresh_token"]
        logger.info("Refresh token found in request body")

    # 2. Из заголовка Authorization
    if not refresh_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            refresh_token = auth_header.replace("Bearer ", "")
            logger.info("Refresh token found in Authorization header")

    if not refresh_token:
        logger.warning("Refresh token not provided")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token not provided"
        )

    try:
        # Проверяем, что токен принадлежит администратору
        payload = await decode_token(refresh_token)

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id = payload.get("sub")
        user_type = payload.get("user_type")

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Проверяем, что тип пользователя - админ
        if user_type != "admin":
            logger.warning(f"Failed refresh attempt: Token user type {user_type} is not 'admin'")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid admin token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Проверяем, что пользователь существует в таблице администраторов
        admin_result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
        admin = admin_result.scalar_one_or_none()

        if not admin:
            logger.warning(f"Failed refresh attempt: ID {user_id} not found in admins table")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid admin token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Вызываем функцию обновления токенов
        logger.info(f"Refreshing admin tokens for ID: {user_id}")

        # Отзываем использованный refresh токен
        await revoke_token(refresh_token, delay_seconds=0)  # Сразу отзываем без задержки

        # Создаем новые токены только если user_id валидный
        access_token = await create_access_token({"sub": user_id}, user_type="admin")
        new_refresh_token = await create_refresh_token({"sub": user_id}, user_type="admin")

        tokens = {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "sub": user_id,
        }

        # Больше не устанавливаем cookies

        logger.info("Admin tokens successfully refreshed")

        # Возвращаем новые токены в теле ответа
        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="bearer"
        )

    except HTTPException as e:
        # Перебрасываем ошибку дальше
        logger.error(f"HTTP exception during admin token refresh: {e.detail}")
        raise e
    except Exception as e:
        # Логируем неожиданную ошибку
        logger.error(f"Unexpected error during admin token refresh: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh admin tokens"
        )
