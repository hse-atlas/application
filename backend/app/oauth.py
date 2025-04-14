from urllib.parse import urlencode
from uuid import UUID
import httpx
import secrets
import string
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from app.config import get_oauth_config
from app.core import add_admin, add_user
from app.database import async_session_maker
from app.jwt_auth import create_access_token, create_refresh_token
from app.schemas import AdminsBase, UsersBase
from app.security import get_password_hash, password_meets_requirements

import logging

logger = logging.getLogger('oauth')

router = APIRouter(prefix='/api/auth/oauth', tags=['OAuth Authentication'])

# Конфигурация OAuth провайдеров
OAUTH_PROVIDERS = get_oauth_config()


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Начало OAuth процесса для администраторов
@router.get("/admin/{provider}")
async def admin_oauth_login(provider: str, request: Request):
    logger.info(f"Starting OAuth login for admin with provider: {provider}")

    if provider not in OAUTH_PROVIDERS:
        logger.warning(f"Unsupported OAuth provider: {provider}")
        raise HTTPException(status_code=404, detail=f"OAuth provider {provider} not supported")

    provider_config = OAUTH_PROVIDERS[provider]

    # Создаем state для защиты от CSRF
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    request.session["user_type"] = "admin"

    # Формируем параметры для URL авторизации
    params = {
        "client_id": provider_config["client_id"],
        "redirect_uri": provider_config["redirect_uri"],
        "scope": provider_config["scope"],
        "response_type": "code",
        "state": state
    }

    # Для VK добавляем версию API
    if provider == "vk":
        params["v"] = provider_config["v"]

    auth_url = f"{provider_config['authorize_url']}?{urlencode(params)}"
    logger.info(f"Generated OAuth authorization URL for {provider}")
    return RedirectResponse(auth_url)


# Обработчик для callback от Google
@router.get("/google/callback")
async def google_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    logger.info("Processing Google OAuth callback")
    return await process_oauth_callback("google", code, state, request, session)


# Обработчик для callback от GitHub
@router.get("/github/callback")
async def github_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    logger.info("Processing GitHub OAuth callback")
    return await process_oauth_callback("github", code, state, request, session)


# Обработчик для callback от Yandex
@router.get("/yandex/callback")
async def yandex_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    logger.info("Processing Yandex OAuth callback")
    return await process_oauth_callback("yandex", code, state, request, session)


# Обработчик для callback от VK
@router.get("/vk/callback")
async def vk_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    logger.info("Processing VK OAuth callback")
    return await process_oauth_callback("vk", code, state, request, session)


# Общая функция для обработки callback от OAuth провайдеров
async def process_oauth_callback(provider: str, code: str, state: str, request: Request, session: AsyncSession):
    logger.info(f"Starting OAuth callback processing for {provider}")

    # Проверка state для защиты от CSRF
    if state != request.session.get("oauth_state"):
        logger.error(f"Invalid state parameter for {provider}")
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    provider_config = OAUTH_PROVIDERS[provider]
    user_type = request.session.get("user_type", "admin")
    logger.info(f"User type from session: {user_type}")

    # Обмен кода на токен
    token_data = {
        "client_id": provider_config["client_id"],
        "client_secret": provider_config["client_secret"],
        "code": code,
        "redirect_uri": provider_config["redirect_uri"],
        "grant_type": "authorization_code"
    }

    headers = {"Accept": "application/json"}
    async with httpx.AsyncClient() as client:
        logger.info(f"Exchanging code for token with URL: {provider_config['token_url']}")
        response = await client.post(provider_config['token_url'], data=token_data, headers=headers)
        logger.info(f"Token response status: {response.status_code}")

        if response.status_code != 200:
            logger.error(f"Failed to obtain token. Status: {response.status_code}, Response: {response.text}")
            raise HTTPException(status_code=400,
                                detail=f"Failed to obtain access token. Provider response: {response.text}")

        # Обработка токена в зависимости от провайдера
        if provider == "github" and response.headers.get("content-type") == "application/x-www-form-urlencoded":
            from urllib.parse import parse_qs
            token_response = parse_qs(response.text)
            access_token = token_response.get("access_token", [""])[0]
        else:
            token_response = response.json()
            access_token = token_response.get("access_token")

        if not access_token:
            logger.error(f"Access token not found in response: {token_response}")
            raise HTTPException(status_code=400, detail="Failed to obtain access token")

        # Получение информации о пользователе
        user_info_headers = {"Authorization": f"Bearer {access_token}"}

        # Особая обработка для VK
        user_info_params = {}
        if provider == "vk":
            user_info_params = {
                "fields": "email",
                "access_token": access_token,
                "v": provider_config["v"]
            }
            user_info_headers = {}

        logger.info(f"Getting user info from URL: {provider_config['userinfo_url']}")
        user_info_response = await client.get(
            provider_config['userinfo_url'],
            params=user_info_params,
            headers=user_info_headers
        )
        logger.info(f"User info response status: {user_info_response.status_code}")

        if user_info_response.status_code != 200:
            logger.error(
                f"Failed to get user info. Status: {user_info_response.status_code}, Response: {user_info_response.text}")
            raise HTTPException(status_code=400,
                                detail=f"Failed to get user info. Provider response: {user_info_response.text}")

        user_info = user_info_response.json()
        logger.info(f"User info received: {user_info}")

        # Извлечение email и имени
        email, name = extract_user_info(provider, user_info, token_response)
        logger.info(f"Extracted user info: email={email}, name={name}")

        if user_type == "admin":
            response = await process_admin_oauth(email, name, provider, user_info.get("id"), session)
        else:
            # Получаем project_id из сессии
            project_id = request.session.get("project_id")
            if not project_id:
                logger.error("Missing project_id in session")
                raise HTTPException(status_code=400, detail="Missing project_id")

            response = await process_user_oauth(email, name, provider, user_info.get("id"), int(project_id), session)

        # Очистка сессии
        logger.info("OAuth process completed successfully, cleaning up session")
        del request.session["oauth_state"]
        if "user_type" in request.session:
            del request.session["user_type"]
        if "project_id" in request.session:
            del request.session["project_id"]

        return response


# Функция для извлечения email и имени из ответа разных провайдеров
def extract_user_info(provider: str, user_info, token_response=None):
    if provider == "google":
        email = user_info.get("email")
        name = user_info.get("name") or user_info.get("given_name", "")
    elif provider == "github":
        email = user_info.get("email")
        name = user_info.get("login") or user_info.get("name", "")
    elif provider == "yandex":
        email = user_info.get("default_email")
        name = user_info.get("display_name") or user_info.get("real_name", "")
    elif provider == "vk":
        # VK возвращает email в токене, а не в user_info
        email = token_response.get("email") if token_response else None
        if user_info.get("response") and len(user_info["response"]) > 0:
            user = user_info["response"][0]
            name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
        else:
            name = ""
    else:
        email = None
        name = "Unknown"

    # Базовая валидация
    if not email:
        raise HTTPException(status_code=400, detail="Email not provided by OAuth provider")

    return email, name


# Обработка OAuth для администраторов
async def process_admin_oauth(email: str, name: str, provider: str, provider_user_id: str, session: AsyncSession):
    from sqlalchemy import select
    logger.info(f"Processing admin OAuth for email={email}, provider={provider}")

    # Проверяем, существует ли уже администратор с таким email
    result = await session.execute(select(AdminsBase).where(AdminsBase.email == email))
    admin = result.scalar_one_or_none()

    if not admin:
        logger.info(f"Admin with email {email} not found, creating new admin")

        # Генерируем случайный пароль для OAuth-пользователя
        password_chars = string.ascii_letters + string.digits + string.punctuation
        random_password = ''.join(secrets.choice(password_chars) for _ in range(16))

        # Используем часть email как логин, если имя не определено
        login = name if name else email.split('@')[0]

        # Проверка уникальности логина
        from app.core import find_one_or_none_admin
        from app.security import get_password_hash
        existing_login = await find_one_or_none_admin(login=login)
        if existing_login:
            logger.info(f"Login {login} already exists, generating unique suffix")
            login = f"{login}_{secrets.token_hex(4)}"

        hashed_password = get_password_hash(random_password)
        admin_data = {
            "email": email,
            "login": login,
            "password": hashed_password,
            "oauth_provider": provider,
            "oauth_user_id": provider_user_id
        }

        logger.info(f"Creating new admin with data: {admin_data}")
        admin = await add_admin(**admin_data)
        logger.info(f"New admin created with ID: {admin.id}")
    elif not admin.oauth_provider:
        # Если администратор существует, но без OAuth, обновляем данные
        logger.info(f"Admin exists but without OAuth, updating OAuth data for admin ID: {admin.id}")
        admin.oauth_provider = provider
        admin.oauth_user_id = provider_user_id
        await session.commit()
    else:
        logger.info(f"Admin already exists with ID: {admin.id}, provider: {admin.oauth_provider}")

    # Создаем JWT токены с использованием стандартного механизма
    logger.info(f"Creating JWT tokens for admin ID: {admin.id}")
    access_token = await create_access_token({"sub": str(admin.id)})
    refresh_token = await create_refresh_token({"sub": str(admin.id)})

    logger.info(
        f"Tokens created - Access token JTI: {access_token.get('jti')}, Refresh token JTI: {refresh_token.get('jti')}")

    # Обновляем last_login
    admin.last_login = datetime.now()
    await session.commit()
    logger.info(f"Updated last_login for admin ID: {admin.id}")

    # Создаем ответ с перенаправлением и передаем токены как параметры URL
    response = RedirectResponse(url=f"/?access_token={access_token}&refresh_token={refresh_token}")

    # Устанавливаем токены в cookie
    response.set_cookie(
        key="admins_access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )
    response.set_cookie(
        key="admins_refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )

    logger.info("Setting cookies with tokens")
    logger.info("OAuth authentication successful, redirecting to dashboard")

    return response


# Обработка OAuth для пользователей проекта
async def process_user_oauth(email: str, name: str, provider: str, provider_user_id: str, project_id: int,
                             session: AsyncSession):
    from sqlalchemy import select
    logger.info(f"Processing user OAuth for email={email}, project_id={project_id}")

    # Проверяем существование проекта
    from app.schemas import ProjectsBase
    result = await session.execute(select(ProjectsBase).where(ProjectsBase.id == project_id))
    project = result.scalar_one_or_none()

    if not project:
        logger.error(f"Project with ID {project_id} not found")
        raise HTTPException(status_code=404, detail="Project not found")

    # Проверяем существование пользователя в проекте
    result = await session.execute(
        select(UsersBase).where(
            UsersBase.email == email,
            UsersBase.project_id == str(project_id)
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        logger.info(f"User with email {email} not found in project, creating new user")

        # Генерируем случайный пароль для OAuth-пользователя
        password_chars = string.ascii_letters + string.digits + string.punctuation
        random_password = ''.join(secrets.choice(password_chars) for _ in range(16))

        # Используем часть email как логин, если имя не определено
        login = name if name else email.split('@')[0]

        # Проверка уникальности логина в рамках проекта
        from app.core import find_one_or_none_user
        from app.security import get_password_hash
        existing_login = await find_one_or_none_user(login=login, project_id=str(project_id))
        if existing_login:
            logger.info(f"Login {login} already exists, generating unique suffix")
            login = f"{login}_{secrets.token_hex(4)}"

        hashed_password = get_password_hash(random_password)
        user_data = {
            "email": email,
            "login": login,
            "password": hashed_password,
            "project_id": str(project_id),
            "oauth_provider": provider,
            "oauth_user_id": provider_user_id
        }

        logger.info(f"Creating new user with data: {user_data}")
        user = await add_user(**user_data)
        logger.info(f"New user created with ID: {user.id}")
    elif not user.oauth_provider:
        # Если пользователь существует, но без OAuth, обновляем данные
        logger.info(f"User exists but without OAuth, updating OAuth data for user ID: {user.id}")
        user.oauth_provider = provider
        user.oauth_user_id = provider_user_id
        await session.commit()
    else:
        logger.info(f"User already exists with ID: {user.id}, provider: {user.oauth_provider}")

    # Создаем JWT токены с использованием стандартного механизма
    logger.info(f"Creating JWT tokens for user ID: {user.id}")
    access_token = await create_access_token({"sub": str(user.id)})
    refresh_token = await create_refresh_token({"sub": str(user.id)})

    logger.info(
        f"Tokens created - Access token JTI: {access_token.get('jti')}, Refresh token JTI: {refresh_token.get('jti')}")

    # Обновляем last_login
    user.last_login = datetime.now()
    await session.commit()
    logger.info(f"Updated last_login for user ID: {user.id}")

    # Создаем ответ с перенаправлением и передаем токены как параметры URL
    response = RedirectResponse(url=f"/projects/{project_id}?access_token={access_token}&refresh_token={refresh_token}")

    # Устанавливаем токены в cookie
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

    logger.info("Setting cookies with tokens")
    logger.info("OAuth authentication successful, redirecting to project page")

    return response