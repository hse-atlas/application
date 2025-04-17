# Добавлено: Импорт Tuple
from typing import Optional, Tuple
from urllib.parse import urlencode, parse_qs
from uuid import UUID
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone # Добавлено: timezone
import secrets
import logging

from app.config import get_oauth_config
from app.core import add_admin, add_user, find_one_or_none_admin, find_one_or_none_user
from app.database import async_session_maker
from app.jwt_auth import create_access_token, create_refresh_token
from app.schemas import AdminsBase, UsersBase, ProjectsBase, UserStatus # Добавлено: UserStatus
from app.security import get_password_hash
from sqlalchemy.future import select

router = APIRouter(prefix='/api/auth/oauth', tags=['OAuth Authentication'])

# Логгер для OAuth
logger = logging.getLogger('oauth')

# Конфигурация OAuth провайдеров
OAUTH_PROVIDERS = get_oauth_config()


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Начало OAuth процесса для администраторов (без изменений)
@router.get("/admin/{provider}")
async def admin_oauth_login(provider: str, request: Request):
    logger.info(f"Admin OAuth login initiated for provider: {provider}")
    if provider not in OAUTH_PROVIDERS:
        logger.error(f"Unsupported OAuth provider requested: {provider}")
        raise HTTPException(status_code=404, detail=f"OAuth provider {provider} not supported")

    provider_config = OAUTH_PROVIDERS[provider]
    if not all(provider_config.get(k) for k in ["client_id", "client_secret"]):
         logger.error(f"OAuth provider '{provider}' is not configured properly (missing client_id or client_secret).")
         raise HTTPException(status_code=503, detail=f"OAuth provider {provider} not configured")

    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    request.session["user_type"] = "admin"
    logger.debug(f"Generated state for admin OAuth: {state}")

    params = {
        "client_id": provider_config["client_id"],
        "redirect_uri": provider_config["redirect_uri"],
        "scope": provider_config["scope"],
        "response_type": "code",
        "state": state
    }
    if provider == "vk":
        params["v"] = provider_config.get("v", "5.131")

    auth_url = f"{provider_config['authorize_url']}?{urlencode(params)}"
    logger.info(f"Redirecting admin to OAuth provider URL: {auth_url}")
    return RedirectResponse(auth_url)


# Начало OAuth процесса для пользователей проекта (без изменений)
@router.get("/user/{provider}/{project_id}")
async def user_oauth_login(
        provider: str,
        project_id: UUID,
        request: Request,
        session: AsyncSession = Depends(get_async_session)):
    logger.info(f"User OAuth login initiated for provider: {provider}, project: {project_id}")
    if provider not in OAUTH_PROVIDERS:
        logger.error(f"Unsupported OAuth provider requested: {provider}")
        raise HTTPException(status_code=404, detail=f"OAuth provider {provider} not supported")

    provider_config = OAUTH_PROVIDERS[provider]
    if not all(provider_config.get(k) for k in ["client_id", "client_secret"]):
         logger.error(f"OAuth provider '{provider}' is not configured properly (missing client_id or client_secret).")
         raise HTTPException(status_code=503, detail=f"OAuth provider {provider} not configured")

    project_result = await session.execute(select(ProjectsBase).where(ProjectsBase.id == str(project_id)))
    project = project_result.scalar_one_or_none()

    if not project:
        logger.error(f"Project not found for OAuth login: {project_id}")
        raise HTTPException(status_code=404, detail="Project not found")

    if not project.oauth_enabled:
        logger.warning(f"OAuth is disabled for project {project_id}")
        raise HTTPException(status_code=403, detail="OAuth authentication is not enabled for this project")

    project_providers_config = project.oauth_providers or {}
    specific_provider_config = project_providers_config.get(provider, {})
    if not specific_provider_config.get("enabled", False):
        logger.warning(f"Provider '{provider}' is disabled for project {project_id}")
        raise HTTPException(status_code=403, detail=f"Provider '{provider}' is not enabled for this project")

    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    request.session["user_type"] = "user"
    request.session["project_id"] = str(project_id)
    logger.debug(f"Generated state for user OAuth: {state}, project_id: {project_id}")

    params = {
        "client_id": provider_config["client_id"],
        "redirect_uri": provider_config["redirect_uri"],
        "scope": provider_config["scope"],
        "response_type": "code",
        "state": state
    }
    if provider == "vk":
        params["v"] = provider_config.get("v", "5.131")

    auth_url = f"{provider_config['authorize_url']}?{urlencode(params)}"
    logger.info(f"Redirecting user to OAuth provider URL: {auth_url}")
    return RedirectResponse(auth_url)


# Обработчики callback (без изменений)
@router.get("/google/callback")
async def google_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("google", code, state, request, session)

@router.get("/github/callback")
async def github_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("github", code, state, request, session)

@router.get("/yandex/callback")
async def yandex_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("yandex", code, state, request, session)

@router.get("/vk/callback")
async def vk_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("vk", code, state, request, session)


# Общая функция для обработки callback от OAuth провайдеров (без изменений в логике, только импорт Tuple)
async def process_oauth_callback(provider: str, code: str, state: str, request: Request, session: AsyncSession):
    logger.info(f"OAuth callback started for provider: {provider}")
    session_state = request.session.get("oauth_state")
    logger.debug(f"State from session: {session_state}, Received state: {state}")

    if not session_state or state != session_state:
        logger.error(f"Invalid state parameter. Session state: {session_state}, Received state: {state}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state parameter")

    provider_config = OAUTH_PROVIDERS.get(provider)
    if not provider_config:
         logger.error(f"Configuration for provider '{provider}' not found during callback.")
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="OAuth provider configuration error")

    user_type = request.session.get("user_type")
    if not user_type:
         logger.error("Missing 'user_type' in session during OAuth callback.")
         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Session expired or invalid user type")
    logger.info(f"User type from session: {user_type}")

    token_data = {
        "client_id": provider_config["client_id"],
        "client_secret": provider_config["client_secret"],
        "code": code,
        "redirect_uri": provider_config["redirect_uri"],
        "grant_type": "authorization_code"
    }
    headers = {"Accept": "application/json"}

    try:
        async with httpx.AsyncClient() as client:
            logger.info(f"Exchanging code for token with URL: {provider_config['token_url']}")
            response = await client.post(provider_config["token_url"], data=token_data, headers=headers)
            logger.info(f"Token exchange response status: {response.status_code}")
            response.raise_for_status()

            if provider == "github" and "application/x-www-form-urlencoded" in response.headers.get("content-type", ""):
                token_response = parse_qs(response.text)
                access_token = token_response.get("access_token", [None])[0]
                logger.debug(f"GitHub token parsed from form data.")
            else:
                token_response = response.json()
                access_token = token_response.get("access_token")
                logger.debug(f"Token received from provider: {token_response}")

            if not access_token:
                logger.error(f"Access token not found in response: {token_response}")
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to obtain access token from provider")
            token_preview = access_token[:10] + "..."
            logger.info(f"Access token obtained, starts with: {token_preview}")

            user_info_headers = {"Authorization": f"Bearer {access_token}"}
            user_info_params = {}
            if provider == "vk":
                user_info_params = {
                    "fields": "email,screen_name",
                    "access_token": access_token,
                    "v": provider_config.get("v", "5.131")
                }
                user_info_headers = {}

            logger.info(f"Getting user info from URL: {provider_config['userinfo_url']}")
            user_info_response = await client.get(
                provider_config["userinfo_url"],
                params=user_info_params,
                headers=user_info_headers
            )
            logger.info(f"User info response status: {user_info_response.status_code}")
            user_info_response.raise_for_status()
            user_info = user_info_response.json()
            logger.info(f"User info received: {user_info}")

            email, name, provider_user_id = extract_user_info(provider, user_info, token_response)
            logger.info(f"Extracted user info: email={email}, name={name}, provider_id={provider_user_id}")

            if not provider_user_id:
                logger.error(f"Could not extract provider's user ID for {provider}")
                raise HTTPException(status_code=500, detail="Failed to get user ID from provider")

            if user_type == "admin":
                logger.info(f"Processing admin OAuth callback for email={email}")
                final_response = await process_admin_oauth(email, name, provider, str(provider_user_id), session)
            else: # user_type == "user"
                project_id_str = request.session.get("project_id")
                if not project_id_str:
                    logger.error("Missing project_id in session for user OAuth callback.")
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing project context")
                try:
                    project_id = UUID(project_id_str)
                except ValueError:
                     logger.error(f"Invalid project_id format in session: {project_id_str}")
                     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid project context")

                logger.info(f"Processing user OAuth callback for email={email}, project_id={project_id}")
                final_response = await process_user_oauth(email, name, provider, str(provider_user_id), project_id, session)

            logger.info("OAuth process completed successfully, cleaning up session state.")
            if "oauth_state" in request.session: del request.session["oauth_state"]
            if "user_type" in request.session: del request.session["user_type"]
            if "project_id" in request.session: del request.session["project_id"]

            return final_response

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error during OAuth callback for {provider}: {e.response.status_code} - {e.response.text}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"OAuth provider error: {e.response.text}")
    except Exception as e:
        logger.error(f"Unexpected error during OAuth callback processing for {provider}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during OAuth processing")


# Функция для извлечения email, имени и ID пользователя из ответа разных провайдеров
# Изменено: Добавлен импорт Tuple в начале файла
def extract_user_info(provider: str, user_info, token_response=None) -> Tuple[str, str, str]:
    email = None
    name = None
    provider_user_id = None

    try:
        if provider == "google":
            email = user_info.get("email")
            name = user_info.get("name") or user_info.get("given_name", "")
            provider_user_id = user_info.get("sub")
        elif provider == "github":
            email = user_info.get("email")
            name = user_info.get("login") or user_info.get("name", "")
            provider_user_id = user_info.get("id")
        elif provider == "yandex":
            email = user_info.get('default_email')
            if not email and 'emails' in user_info:
                emails = user_info.get('emails', [])
                email = emails[0] if emails else None
            name = user_info.get('display_name') or user_info.get('real_name', '') or user_info.get('login')
            provider_user_id = user_info.get("id")
        elif provider == "vk":
            if token_response:
                email = token_response.get("email")
            if user_info.get("response") and len(user_info["response"]) > 0:
                vk_user = user_info["response"][0]
                if not email: email = vk_user.get("email")
                name = f"{vk_user.get('first_name', '')} {vk_user.get('last_name', '')}".strip()
                if not name: name = vk_user.get("screen_name")
                provider_user_id = vk_user.get("id")
        else:
             logger.error(f"Extraction logic not implemented for provider: {provider}")

        if not email:
            logger.warning(f"Email not found in OAuth response from {provider}. User Info: {user_info}, Token Resp: {token_response}")
            raise HTTPException(status_code=400, detail="Email not provided by OAuth provider or permission denied.")
        if not name:
            name = email.split('@')[0]
            logger.warning(f"Name not found for provider {provider}, generated from email: {name}")
        if provider_user_id is None:
             logger.error(f"Provider user ID not found for provider {provider}")
             raise ValueError("Provider user ID missing")

        return email, name, str(provider_user_id)

    except (KeyError, IndexError, TypeError, ValueError) as e:
        logger.error(f"Error extracting user info for {provider}: {str(e)}. User Info: {user_info}, Token Resp: {token_response}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to parse user info from {provider}")


# Обработка OAuth для администраторов
async def process_admin_oauth(email: str, name: str, provider: str, provider_user_id: str, session: AsyncSession):
    logger.info(f"Processing admin OAuth for email={email}, provider={provider}, provider_id={provider_user_id}")
    admin = await find_one_or_none_admin(oauth_provider=provider, oauth_user_id=provider_user_id)

    if not admin:
        admin = await find_one_or_none_admin(email=email)
        if admin:
            if not admin.oauth_provider:
                logger.info(f"Found existing admin by email {email}, linking OAuth provider {provider} (ID: {provider_user_id})")
                admin.oauth_provider = provider
                admin.oauth_user_id = provider_user_id
                admin.last_login = datetime.utcnow()
                await session.commit()
                # Изменено: Убираем refresh, он не нужен и вызывает ошибку
                # await session.refresh(admin)
            else:
                logger.error(f"Admin email {email} already linked to another OAuth account ({admin.oauth_provider}). Cannot link {provider}.")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already linked to another authentication method.")
        else:
            logger.info(f"Admin with email {email} not found, creating new admin via OAuth {provider}")
            login = name if name else email.split('@')[0]
            counter = 0
            base_login = login
            while await find_one_or_none_admin(login=login):
                counter += 1; login = f"{base_login}_{counter}"
            admin_data = {
                "email": email, "login": login, "password": None,
                "oauth_provider": provider, "oauth_user_id": provider_user_id,
                "last_login": datetime.utcnow()
            }
            admin = await add_admin(**admin_data) # add_admin вернет уже "прикрепленный" объект
            logger.info(f"New admin created via OAuth: ID={admin.id}, login={admin.login}")
            # Здесь refresh не нужен, т.к. add_admin возвращает объект из сессии после commit
    else:
        logger.info(f"Found existing admin by OAuth {provider} ID {provider_user_id}. Updating last login.")
        admin.last_login = datetime.utcnow()
        await session.commit()
        # Изменено: Убираем refresh, он не нужен и вызывает ошибку
        # await session.refresh(admin)

    logger.info(f"Creating JWT tokens for admin ID: {admin.id}")
    access_token = await create_access_token({"sub": str(admin.id)}, user_type="admin")
    refresh_token = await create_refresh_token({"sub": str(admin.id)}, user_type="admin")
    logger.info(f"Tokens created for admin {admin.id}")

    redirect_url = f"/?type=admin&access_token={access_token}&refresh_token={refresh_token}"
    response = RedirectResponse(url=redirect_url)
    logger.info(f"Redirecting admin to: {redirect_url}")
    response.set_cookie(key="admins_access_token", value=access_token, httponly=True, secure=True, samesite="strict")
    response.set_cookie(key="admins_refresh_token", value=refresh_token, httponly=True, secure=True, samesite="strict")
    logger.info("Admin auth cookies set.")
    return response


# Обработка OAuth для пользователей
async def process_user_oauth(email: str, name: str, provider: str, provider_user_id: str, project_id: UUID,
                             session: AsyncSession):
    logger.info(f"Processing user OAuth for email={email}, project_id={project_id}, provider={provider}, provider_id={provider_user_id}")

    # Используем session.get для проверки проекта, т.к. он нужен только для проверки
    project = await session.get(ProjectsBase, str(project_id))
    if not project:
        logger.error(f"Project {project_id} not found during user OAuth processing.")
        raise HTTPException(status_code=404, detail="Project not found")

    user = await find_one_or_none_user(oauth_provider=provider, oauth_user_id=provider_user_id, project_id=str(project_id))

    if not user:
        user = await find_one_or_none_user(email=email, project_id=str(project_id))
        if user:
            if not user.oauth_provider:
                logger.info(f"Found existing user by email {email} in project {project_id}, linking OAuth provider {provider} (ID: {provider_user_id})")
                user.oauth_provider = provider
                user.oauth_user_id = provider_user_id
                user.last_login = datetime.utcnow()
                await session.commit()
                 # Изменено: Убираем refresh
                # await session.refresh(user)
            else:
                 logger.error(f"User email {email} in project {project_id} already linked to another OAuth account ({user.oauth_provider}). Cannot link {provider}.")
                 raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already linked to another authentication method in this project.")
        else:
            logger.info(f"User with email {email} not found in project {project_id}, creating new user via OAuth {provider}")
            login = name if name else email.split('@')[0]
            counter = 0
            base_login = login
            while await find_one_or_none_user(login=login, project_id=str(project_id)):
                counter += 1; login = f"{base_login}_{counter}"
            user_data = {
                "email": email, "login": login, "password": None,
                "project_id": str(project_id), "role": "user", "status": UserStatus.ACTIVE,
                "oauth_provider": provider, "oauth_user_id": provider_user_id,
                "last_login": datetime.utcnow()
            }
            user = await add_user(**user_data) # add_user возвращает персистентный объект
            logger.info(f"New user created via OAuth: ID={user.id}, login={user.login}, project={project_id}")
            # Refresh не нужен
    else:
         logger.info(f"Found existing user by OAuth {provider} ID {provider_user_id} in project {project_id}. Updating last login.")
         if user.status == UserStatus.BLOCKED:
              logger.warning(f"OAuth login failed for user {user.id} ({email}): account is blocked.")
              raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is blocked")
         user.last_login = datetime.utcnow()
         await session.commit()
         # Изменено: Убираем refresh
         # await session.refresh(user)

    logger.info(f"Creating JWT tokens for user ID: {user.id}")
    access_token = await create_access_token({"sub": str(user.id)}, user_type="user")
    refresh_token = await create_refresh_token({"sub": str(user.id)}, user_type="user")
    logger.info(f"Tokens created for user {user.id}")

    redirect_url = f"/?type=user&project_id={project_id}&access_token={access_token}&refresh_token={refresh_token}"
    response = RedirectResponse(url=redirect_url)
    logger.info(f"Redirecting user to: {redirect_url}")
    response.set_cookie(key="users_access_token", value=access_token, httponly=True, secure=True, samesite="strict")
    response.set_cookie(key="users_refresh_token", value=refresh_token, httponly=True, secure=True, samesite="strict")
    logger.info("User auth cookies set.")
    return response