from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from app.config import get_oauth_config
from app.core import add_admin, add_user
from app.database import async_session_maker
from app.jwt_auth import create_access_token, create_refresh_token
from app.schemas import AdminsBase, UsersBase

router = APIRouter(prefix="/oauth", tags=["OAuth Authentication"])

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
async def user_oauth_login(provider: str, project_id: int, request: Request,
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
    # Проверка state для защиты от CSRF
    if state != request.session.get("oauth_state"):
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    provider_config = OAUTH_PROVIDERS[provider]
    user_type = request.session.get("user_type", "admin")

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
        response = await client.post(provider_config["token_url"], data=token_data, headers=headers)

        if provider == "github" and response.headers.get("content-type") == "application/x-www-form-urlencoded":
            # GitHub может вернуть данные в формате x-www-form-urlencoded
            from urllib.parse import parse_qs
            token_response = parse_qs(response.text)
            access_token = token_response.get("access_token", [""])[0]
        else:
            token_response = response.json()
            access_token = token_response.get("access_token")

        if not access_token:
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

        user_info_response = await client.get(
            provider_config["userinfo_url"],
            params=user_info_params,
            headers=user_info_headers
        )
        user_info = user_info_response.json()

        # Извлечение email и имени из разных провайдеров
        email, name = extract_user_info(provider, user_info, token_response)

        if user_type == "admin":
            # Регистрация или авторизация администратора
            response = await process_admin_oauth(email, name, provider, user_info.get("id"), session)
        else:
            # Регистрация или авторизация пользователя
            project_id = request.session.get("project_id")
            if not project_id:
                raise HTTPException(status_code=400, detail="Missing project_id")
            response = await process_user_oauth(email, name, provider, user_info.get("id"), int(project_id), session)

        # Очистка сессии
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

    # Проверяем, существует ли уже администратор с таким email
    result = await session.execute(select(AdminsBase).where(AdminsBase.email == email))
    admin = result.scalar_one_or_none()

    if not admin:
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
            login = f"{login}_{secrets.token_hex(4)}"

        hashed_password = get_password_hash(random_password)
        admin_data = {
            "email": email,
            "login": login,
            "password": hashed_password,
            "oauth_provider": provider,
            "oauth_user_id": provider_user_id
        }

        admin = await add_admin(**admin_data)
    elif not admin.oauth_provider:
        # Если администратор существует, но без OAuth, обновляем данные
        admin.oauth_provider = provider
        admin.oauth_user_id = provider_user_id
        await session.commit()

    # Создаем JWT токен
    access_token = await create_access_token({"sub": str(admin.id)})
    refresh_token = await create_refresh_token({"sub": str(admin.id)})

    # Обновляем last_login
    admin.last_login = datetime.now()
    admin.last_login = datetime.now()
    await session.commit()

    # Создаем ответ с редиректом
    response = RedirectResponse(url="/dashboard")  # Редирект на дашборд
    response.set_cookie(key="admins_access_token", value=access_token, httponly=True, secure=True, samesite="strict")
    response.set_cookie(key="admins_refresh_token", value=refresh_token, httponly=True, secure=True, samesite="strict")

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

    # Создаем JWT токен
    access_token = await create_access_token({"sub": str(user.id)})
    refresh_token = await create_refresh_token({"sub": str(user.id)})

    # Обновляем last_login
    from datetime import datetime
    user.last_login = datetime.now()
    await session.commit()

    # Редирект на страницу приложения/проекта
    response = RedirectResponse(url=f"/projects/{project_id}")
    response.set_cookie(key="users_access_token", value=access_token, httponly=True, secure=True, samesite="strict")
    response.set_cookie(key="users_refresh_token", value=refresh_token, httponly=True, secure=True, samesite="strict")

    return response
