from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_maker
from app.jwt_auth import create_access_token, create_refresh_token
from app.schemas import RegisterData, LoginData, TokenResponse
from app.security import verify_password, get_password_hash, password_meets_requirements

# Создаем лимитер для защиты от брутфорс-атак
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/api/v1/AuthService", tags=["Auth API"])


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Регистрация пользователя в рамках проекта
@router.post("/user_register/{project_id}", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def user_register(
        request: Request,
        project_id: int,
        user_data: RegisterData,
        db: AsyncSession = Depends(get_async_session)
):
    # Проверка существования проекта
    from app.schemas import ProjectsBase
    from sqlalchemy.future import select

    project_result = await db.execute(select(ProjectsBase).where(ProjectsBase.id == project_id))
    project = project_result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )

    # Проверка email
    from app.core import find_one_or_none_user
    existing_user_email = await find_one_or_none_user(email=user_data.email, project_id=project_id)
    if existing_user_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="E-mail already registered in this project"
        )

    # Проверка логина
    existing_user_login = await find_one_or_none_user(login=user_data.login, project_id=project_id)
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
    user_dict['project_id'] = project_id

    from app.core import add_user
    new_user = await add_user(**user_dict)

    return {'message': 'User registration completed successfully!', 'user_id': new_user.id}


# Авторизация пользователя в рамках проекта
@router.post("/user_login/{project_id}", response_model=TokenResponse)
@limiter.limit("10/minute")
async def user_login(
        request: Request,
        project_id: int,
        user_data: LoginData,
        response: Response,
        db: AsyncSession = Depends(get_async_session)
):
    # Поиск пользователя по email и project_id
    from sqlalchemy.future import select
    from app.schemas import UsersBase

    result = await db.execute(
        select(UsersBase).where(
            UsersBase.email == user_data.email,
            UsersBase.project_id == project_id
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Проверка пароля
    if not verify_password(user_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Генерация токенов
    access_token = await create_access_token({"sub": str(user.id)})
    refresh_token = await create_refresh_token({"sub": str(user.id)})

    # Установка токенов в cookie
    response.set_cookie(
        key="users_access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )

    response.set_cookie(
        key="users_refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )
