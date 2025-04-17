from uuid import UUID
# Добавляем импорты для нового эндпоинта
from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import cast, String
from sqlalchemy.future import select
import logging

from app.database import async_session_maker
# Импортируем нужные функции JWT и зависимости
from app.jwt_auth import create_access_token, create_refresh_token, get_current_project_user
# Импортируем схемы и модели
from app.schemas import (
    RegisterData, LoginData, TokenResponse, ProjectsBase,
    UserStatus, UsersBase, UserOut # Добавляем UserOut для ответа /me
)
from app.security import verify_password, get_password_hash, password_meets_requirements


# Создаем лимитер для защиты от брутфорс-атак
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix='/api/auth/user', tags=['User Auth'])

logger = logging.getLogger('auth') # Используем логгер 'auth'

async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Регистрация пользователя в рамках проекта (без изменений)
@router.post("/register/{project_id}", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def user_register(
        request: Request,
        project_id: UUID,
        user_data: RegisterData,
        db: AsyncSession = Depends(get_async_session)
):
    logger.info(f"User registration attempt for project {project_id}: email={user_data.email}, login={user_data.login}")
    # Проверка существования проекта
    project_result = await db.execute(
        select(ProjectsBase).where(
            cast(ProjectsBase.id, String) == str(project_id) # Сравнение со строкой
        )
    )
    project = project_result.scalar_one_or_none()

    if not project:
        logger.warning(f"User registration failed: project {project_id} not found.")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )

    # Проверка email
    from app.core import find_one_or_none_user
    existing_user_email = await find_one_or_none_user(email=user_data.email, project_id=str(project_id))
    if existing_user_email:
        logger.warning(f"User registration failed: email {user_data.email} already exists in project {project_id}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="E-mail already registered in this project"
        )

    # Проверка логина
    existing_user_login = await find_one_or_none_user(login=user_data.login, project_id=str(project_id))
    if existing_user_login:
        logger.warning(f"User registration failed: login {user_data.login} already exists in project {project_id}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Login already exists in this project"
        )

    # Проверка сложности пароля
    is_valid, error_message = password_meets_requirements(user_data.password)
    if not is_valid:
        logger.warning(f"User registration failed: password for {user_data.email} doesn't meet requirements. Error: {error_message}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    try:
        # Хеширование пароля и добавление пользователя
        user_dict = user_data.dict()
        user_dict['password'] = get_password_hash(user_data.password)
        user_dict['project_id'] = str(project_id)
        user_dict['status'] = UserStatus.ACTIVE # Явно устанавливаем статус при регистрации
        user_dict['role'] = 'user' # Явно устанавливаем роль

        from app.core import add_user
        new_user = await add_user(**user_dict)
        logger.info(f"User registered successfully for project {project_id}: id={new_user.id}, email={user_data.email}")

        return {'message': 'User registration completed successfully!', 'user_id': new_user.id}
    except Exception as e:
        logger.error(f"Error during user registration for project {project_id}, email={user_data.email}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Registration failed due to server error'
        )


# Авторизация пользователя в рамках проекта
@router.post("/login/{project_id}", response_model=TokenResponse)
@limiter.limit("10/minute")
async def user_login(
        request: Request,
        project_id: UUID,
        user_data: LoginData,
        response: Response,
        db: AsyncSession = Depends(get_async_session)
):
    logger.info(f"User login attempt for project {project_id}: email={user_data.email}")
    # Поиск пользователя по email и project_id
    result = await db.execute(
        select(UsersBase).where(
            UsersBase.email == user_data.email,
            cast(UsersBase.project_id, String) == str(project_id) # Сравнение со строкой
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        logger.warning(f"User login failed: email {user_data.email} not found in project {project_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password for this project" # Уточнили сообщение
        )

    # Проверка статуса пользователя
    if user.status == UserStatus.BLOCKED:
        logger.warning(f"User login failed: account {user_data.email} in project {project_id} is blocked.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is blocked in this project. Contact the project administrator."
        )

    # Проверка пароля
    # Добавлено: проверка, что пароль вообще есть (не только OAuth)
    if not user.password:
        logger.warning(f"User login failed: account {user_data.email} in project {project_id} uses OAuth.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Password login not available for this account. Try OAuth.'
        )

    if not verify_password(user_data.password, user.password):
        logger.warning(f"User login failed: incorrect password for {user_data.email} in project {project_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

     # Генерация токенов
    logger.info(f"User login successful for project {project_id}: email={user_data.email}, id={user.id}, role={user.role}") # Логируем роль
    logger.debug(f"Generating tokens for user id={user.id}")
    try:
        # Изменено: Добавляем 'role' в данные для токена
        token_data = {"sub": str(user.id), "role": user.role}

        # Изменено: Передаем token_data и user_type="user"
        access_token = await create_access_token(token_data, user_type="user")
        refresh_token = await create_refresh_token(token_data, user_type="user")

        logger.debug(f"Tokens generated successfully for user id={user.id}")


        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    except Exception as e:
        logger.error(f"Error during token generation for user id={user.id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to generate authentication tokens'
        )

@router.get("/me",
            response_model=UserOut, # Используем схему UserOut для ответа
            tags=["User Auth"], # Тот же тег
            summary="Get current authenticated project user profile")
async def get_current_user_profile(
    # Используем зависимость get_current_project_user,
    # которая уже проверила токен и тип пользователя ('user')
    # и вернула объект UsersBase
    current_user: UsersBase = Depends(get_current_project_user)
):
    """
    Возвращает профиль текущего аутентифицированного пользователя проекта.
    Требует валидный access token пользователя проекта.
    """
    logger.info(f"User profile requested: id={current_user.id}, email={current_user.email}, project_id={current_user.project_id}")
    # Объект current_user уже содержит все необходимые данные (id, login, email, project_id, role, status)
    # Pydantic автоматически преобразует его в модель UserOut
    return current_user