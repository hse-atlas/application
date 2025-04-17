from uuid import UUID
from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import cast, String
from sqlalchemy.future import select

from app.database import async_session_maker
from app.jwt_auth import create_access_token, create_refresh_token, decode_token, revoke_token
from app.schemas import RegisterData, LoginData, TokenResponse, ProjectsBase, UserStatus, UsersBase
from app.security import verify_password, get_password_hash, password_meets_requirements

import logging

# Получаем логгер
logger = logging.getLogger('auth')

# Создаем лимитер для защиты от брутфорс-атак
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix='/api/auth/user', tags=['User Auth'])


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Регистрация пользователя в рамках проекта
@router.post("/register/{project_id}", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def user_register(
        request: Request,
        project_id: UUID,
        user_data: RegisterData,
        db: AsyncSession = Depends(get_async_session)
):
    # Проверка существования проекта
    project_result = await db.execute(
        select(ProjectsBase).where(
            cast(ProjectsBase.id, String) == str(project_id)
        )
    )
    project = project_result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )

    # Проверка email
    from app.core import find_one_or_none_user
    existing_user_email = await find_one_or_none_user(email=user_data.email, project_id=str(project_id))
    if existing_user_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="E-mail already registered in this project"
        )

    # Проверка логина
    existing_user_login = await find_one_or_none_user(login=user_data.login, project_id=str(project_id))
    if existing_user_login:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Login already exists in this project"
        )

    # Проверка сложности пароля
    is_valid, error_message = password_meets_requirements(user_data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    # Хеширование пароля и добавление пользователя
    user_dict = user_data.dict()
    user_dict['password'] = get_password_hash(user_data.password)
    user_dict['project_id'] = str(project_id)

    from app.core import add_user
    new_user = await add_user(**user_dict)

    return {'message': 'User registration completed successfully!', 'user_id': new_user.id}


# Авторизация пользователя в рамках проекта
@router.post("/login/{project_id}", response_model=TokenResponse)
@limiter.limit("10/minute")
async def user_login(
        request: Request,
        project_id: UUID,
        user_data: LoginData,
        db: AsyncSession = Depends(get_async_session)
):
    # Поиск пользователя по email и project_id
    result = await db.execute(
        select(UsersBase).where(
            UsersBase.email == user_data.email,
            cast(UsersBase.project_id, String) == str(project_id)
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Проверка статуса пользователя
    if user.status == UserStatus.BLOCKED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ваш аккаунт заблокирован. Обратитесь к администратору проекта."
        )

    # Проверка пароля
    if not verify_password(user_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Генерация токенов с указанием типа пользователя "user"
    access_token = await create_access_token({"sub": str(user.id)}, user_type="user")
    refresh_token = await create_refresh_token({"sub": str(user.id)}, user_type="user")

    # Больше НЕ устанавливаем токены в cookie

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post("/{project_id}/refresh/", response_model=TokenResponse)
@limiter.limit("20/minute")
async def user_token_refresh(
        request: Request,
        project_id: UUID,
        refresh_data: dict = None,
        db: AsyncSession = Depends(get_async_session)
):
    """
    Обновление токенов пользователя с использованием refresh токена.
    """
    logger.info(f"User token refresh request received for project: {project_id}")

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
        # Проверяем токен
        payload = await decode_token(refresh_token)

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id = payload.get("sub")
        user_type = payload.get("user_type")

        if not user_id or not user_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Проверяем, что тип пользователя - user
        if user_type != "user":
            logger.warning(f"Failed refresh attempt: Token user type {user_type} is not 'user'")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid user token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Проверяем, что пользователь существует в таблице пользователей и принадлежит указанному проекту
        user_result = await db.execute(
            select(UsersBase).where(
                UsersBase.id == int(user_id),
                cast(UsersBase.project_id, String) == str(project_id)
            )
        )
        user = user_result.scalar_one_or_none()

        if not user:
            logger.warning(f"Failed refresh attempt: User ID {user_id} not found in project {project_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid user token or user not in project",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Вызываем функцию обновления токенов
        logger.info(f"Refreshing user tokens for ID: {user_id}")

        # Отзываем использованный refresh токен
        await revoke_token(refresh_token, delay_seconds=0)  # Сразу отзываем без задержки

        # Создаем новые токены с указанием типа пользователя "user"
        access_token = await create_access_token({"sub": user_id}, user_type="user")
        new_refresh_token = await create_refresh_token({"sub": user_id}, user_type="user")

        tokens = {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "sub": user_id,
        }

        # Больше НЕ устанавливаем cookies

        logger.info("User tokens successfully refreshed")

        # Возвращаем новые токены в теле ответа
        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="bearer"
        )

    except HTTPException as e:
        # Перебрасываем ошибку дальше
        logger.error(f"HTTP exception during user token refresh: {e.detail}")
        raise e
    except Exception as e:
        # Логируем неожиданную ошибку
        logger.error(f"Unexpected error during user token refresh: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh user tokens"
        )
