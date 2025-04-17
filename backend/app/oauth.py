from datetime import datetime
from urllib.parse import urlencode
from uuid import UUID

import httpx
from app.config import get_oauth_config
from app.core import add_admin, add_user
from app.database import async_session_maker
from app.jwt_auth import create_access_token, create_refresh_token
from app.schemas import AdminsBase, UsersBase
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix='/api/auth/oauth', tags=['OAuth Authentication'])

# Конфигурация OAuth провайдеров
OAUTH_PROVIDERS = get_oauth_config()


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Начало OAuth процесса для администраторов
@router.get("/admin/{provider}")
async def admin_oauth_login(provider: str, request: Request):
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(status_code=404, detail=f"OAuth provider {provider} not supported")

    provider_config = OAUTH_PROVIDERS[provider]

    # Создаем state для защиты от CSRF
    import secrets
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    request.session["user_type"] = "admin"

    # Формируем URL авторизации
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
    return RedirectResponse(auth_url)


# Начало OAuth процесса для пользователей проекта
@router.get("/user/{provider}/{project_id}")
async def user_oauth_login(
        provider: str,
        project_id: UUID,
        request: Request,
        session: AsyncSession = Depends(get_async_session)):
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(status_code=404, detail=f"OAuth provider {provider} not supported")

    # Проверяем существование проекта
    from sqlalchemy.future import select
    from app.schemas import ProjectsBase

    project_result = await session.execute(select(ProjectsBase).where(ProjectsBase.id == project_id))
    project = project_result.scalar_one_or_none()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Проверяем, включен ли OAuth для проекта
    if not project.oauth_enabled:
        raise HTTPException(status_code=403, detail="OAuth authentication is not enabled for this project")

    # Проверяем, настроен ли запрашиваемый провайдер для проекта
    if project.oauth_providers and provider in project.oauth_providers:
        provider_config = project.oauth_providers[provider]
        if not provider_config.get("enabled", False):
            raise HTTPException(status_code=403, detail=f"{provider} authentication is not enabled for this project")

    provider_config = OAUTH_PROVIDERS[provider]

    # Создаем state для защиты от CSRF и сохраняем project_id
    import secrets
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    request.session["user_type"] = "user"
    request.session["project_id"] = project_id

    # Формируем URL авторизации
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
    return RedirectResponse(auth_url)


# Обработчик для callback от Google
@router.get("/google/callback")
async def google_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("google", code, state, request, session)


# Обработчик для callback от GitHub
@router.get("/github/callback")
async def github_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("github", code, state, request, session)


# Обработчик для callback от Yandex
@router.get("/yandex/callback")
async def yandex_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("yandex", code, state, request, session)


# Обработчик для callback от VK
@router.get("/vk/callback")
async def vk_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("vk", code, state, request, session)


# Общая функция для обработки callback от OAuth провайдеров
async def process_oauth_callback(provider: str, code: str, state: str, request: Request, session: AsyncSession):
    # Добавляем логирование в начале функции
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"OAuth callback started for provider: {provider}")
    logger.info(f"State from session: {request.session.get('oauth_state')}, Received state: {state}")

    # Проверка state для защиты от CSRF
    if state != request.session.get("oauth_state"):
        logger.error(
            f"Invalid state parameter. Session state: {request.session.get('oauth_state')}, Received state: {state}")
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
        response = await client.post(provider_config["token_url"], data=token_data, headers=headers)
        logger.info(f"Token response status: {response.status_code}")

        if response.status_code != 200:
            logger.error(f"Failed to obtain token. Status: {response.status_code}, Response: {response.text}")
            raise HTTPException(status_code=400,
                                detail=f"Failed to obtain access token. Provider response: {response.text}")

        if provider == "github" and response.headers.get("content-type") == "application/x-www-form-urlencoded":
            # GitHub может вернуть данные в формате x-www-form-urlencoded
            from urllib.parse import parse_qs
            token_response = parse_qs(response.text)
            access_token = token_response.get("access_token", [""])[0]
            logger.info(
                f"GitHub token parsed from form data, token starts with: {access_token[:10] if access_token else 'None'}")
        else:
            token_response = response.json()
            access_token = token_response.get("access_token")
            logger.info(
                f"Token received from provider, token starts with: {access_token[:10] if access_token else 'None'}")

        if not access_token:
            logger.error(f"Access token not found in response: {token_response}")
            raise HTTPException(status_code=400, detail="Failed to obtain access token")

        # Получение информации о пользователе
        user_info_headers = {"Authorization": f"Bearer {access_token}"}

        # Для VK добавляем дополнительные параметры
        user_info_params = {}
        if provider == "vk":
            user_info_params = {
                "fields": "email",
                "access_token": access_token,
                "v": provider_config["v"]
            }
            user_info_headers = {}  # VK не использует Authorization header

        logger.info(f"Getting user info from URL: {provider_config['userinfo_url']}")
        user_info_response = await client.get(
            provider_config["userinfo_url"],
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

        # Извлечение email и имени из разных провайдеров
        email, name = extract_user_info(provider, user_info, token_response)
        logger.info(f"Extracted user info: email={email}, name={name}")

        if user_type == "admin":
            # Регистрация или авторизация администратора
            logger.info(f"Processing admin OAuth with email={email}, provider={provider}")
            response = await process_admin_oauth(email, name, provider, user_info.get("id"), session)
        else:
            # Регистрация или авторизация пользователя
            project_id = request.session.get("project_id")
            if not project_id:
                logger.error("Missing project_id in session")
                raise HTTPException(status_code=400, detail="Missing project_id")
            logger.info(f"Processing user OAuth with email={email}, provider={provider}, project_id={project_id}")
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
        # Если email не вернулся в основном запросе, нужно делать дополнительный запрос к emails API
        name = user_info.get("login") or user_info.get("name", "")
    elif provider == "yandex":
        # Явно запрашиваем email из ответа пользователя
        email = user_info.get('default_email')
        # Если email не найден, попробуем извлечь из списка emails
        if not email and 'emails' in user_info:
            # Берем первый доступный email
            emails = user_info.get('emails', [])
            email = emails[0] if emails else None

        # Если по-прежнему нет email, вызываем исключение
        if not email:
            raise HTTPException(
                status_code=400,
                detail="Unable to retrieve email from Yandex OAuth response"
            )
        name = user_info.get('display_name') or user_info.get('real_name', '')
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
    import logging
    logger = logging.getLogger(__name__)

    logger.info(f"Processing admin OAuth for email={email}, provider={provider}")

    # Проверяем, существует ли уже администратор с таким email
    result = await session.execute(select(AdminsBase).where(AdminsBase.email == email))
    admin = result.scalar_one_or_none()

    if not admin:
        logger.info(f"Admin with email {email} not found, creating new admin")
        # Создаем нового администратора
        import secrets
        import string
        # Генерируем случайный пароль, который пользователь не будет использовать (OAuth аутентификация)
        password_chars = string.ascii_letters + string.digits + string.punctuation
        random_password = ''.join(secrets.choice(password_chars) for _ in range(16))

        # Используем часть email как логин, если имя не определено
        login = name if name else email.split('@')[0]

        # Добавляем уникальный суффикс к логину, если нужно
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

    # Создаем JWT токены с указанием типа пользователя "admin"
    logger.info(f"Creating JWT tokens for admin ID: {admin.id}")
    access_token = await create_access_token({"sub": str(admin.id)}, user_type="admin")
    refresh_token = await create_refresh_token({"sub": str(admin.id)}, user_type="admin")
    logger.info(
        f"Tokens created - Access token starts with: {access_token[:10]}, Refresh token starts with: {refresh_token[:10]}")

    # Обновляем last_login
    admin.last_login = datetime.now()
    await session.commit()
    logger.info(f"Updated last_login for admin ID: {admin.id}")

    # Создаем ответ с перенаправлением и передаем токены как параметры URL
    response = RedirectResponse(url=f"/?access_token={access_token}&refresh_token={refresh_token}")

    # Больше НЕ устанавливаем токены в cookie
    logger.info("OAuth authentication successful, redirecting to dashboard")

    return response


# Обработка OAuth для пользователей
async def process_user_oauth(email: str, name: str, provider: str, provider_user_id: str, project_id: int,
                             session: AsyncSession):
    from sqlalchemy import select

    # Проверяем, существует ли проект
    from app.schemas import ProjectsBase
    result = await session.execute(select(ProjectsBase).where(ProjectsBase.id == project_id))
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Проверяем, существует ли уже пользователь с таким email в данном проекте
    result = await session.execute(
        select(UsersBase).where(UsersBase.email == email, UsersBase.project_id == project_id)
    )
    user = result.scalar_one_or_none()

    if not user:
        # Создаем нового пользователя
        import secrets
        import string
        # Генерируем случайный пароль, который пользователь не будет использовать (OAuth аутентификация)
        password_chars = string.ascii_letters + string.digits + string.punctuation
        random_password = ''.join(secrets.choice(password_chars) for _ in range(16))

        # Используем часть email как логин, если имя не определено
        login = name if name else email.split('@')[0]

        # Добавляем уникальный суффикс к логину, если нужно
        from app.core import find_one_or_none_user
        from app.security import get_password_hash
        existing_login = await find_one_or_none_user(login=login, project_id=project_id)
        if existing_login:
            login = f"{login}_{secrets.token_hex(4)}"

        hashed_password = get_password_hash(random_password)
        user_data = {
            "email": email,
            "login": login,
            "password": hashed_password,
            "project_id": project_id,
            "oauth_provider": provider,
            "oauth_user_id": provider_user_id
        }

        user = await add_user(**user_data)
    elif not user.oauth_provider:
        # Если пользователь существует, но без OAuth, обновляем данные
        user.oauth_provider = provider
        user.oauth_user_id = provider_user_id
        await session.commit()

    # Создаем JWT токены с указанием типа пользователя "user"
    access_token = await create_access_token({"sub": str(user.id)}, user_type="user")
    refresh_token = await create_refresh_token({"sub": str(user.id)}, user_type="user")

    # Обновляем last_login
    from datetime import datetime
    user.last_login = datetime.now()
    await session.commit()

    # Редирект на страницу приложения/проекта с передачей токенов в URL
    response = RedirectResponse(url=f"/projects/{project_id}?access_token={access_token}&refresh_token={refresh_token}")

    # Больше НЕ устанавливаем токены в cookie

    return response
