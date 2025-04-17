# Добавлено: Импорт HTTPException
from fastapi import FastAPI, Depends, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from starlette.middleware.sessions import SessionMiddleware
import logging
# Добавлено: Импорт anext для асинхронных генераторов (если используется Python < 3.10)
# или просто используйте async for session in db_session_gen:
from asyncio import anext # Для Python 3.10+, для < 3.10 может потребоваться `async_generator` или другая логика

from app.admin_auth import router as admin_auth_router
from app.user_auth import router as user_auth_router
from app.common_auth import router as common_auth_router
from app.oauth import router as oauth_router
from app.project_CRUD import router as project_crud_router
from app.user_CRUD import router as user_crud_router
from app.user_roles import router as user_roles_router
from app.debug import router as debug_router

from app.database import test_db_connection
from app.config import config
from app.jwt_auth import auth_middleware, get_async_session, redis_client

# --- Код логирования ---
# ... (ваш код настройки логгеров) ...
logger = logging.getLogger(__name__)
logger.info("Logging system initialized")
# --- Конец кода логирования ---

# Создаем лимитер
limiter = Limiter(key_func=get_remote_address)

# Создаем приложение FastAPI
application = FastAPI(
    title="Atlas Auth Service",
    description="Микросервис для управления аутентификацией пользователей",
    version="1.0.0",
    debug=config.DEBUG
)

# Middleware для сессий
application.add_middleware(
    SessionMiddleware,
    secret_key=config.SESSION_SECRET_KEY,
    max_age=1800
)

# Middleware для CORS
application.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware для ограничения запросов
application.add_middleware(SlowAPIMiddleware)
application.state.limiter = limiter

# Обработчик ошибок для превышения лимита запросов
@application.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    from fastapi.responses import JSONResponse
    logger.warning(f"Rate limit exceeded for {get_remote_address(request)}: {exc.detail}")
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"}
    )


# Middleware аутентификации
@application.middleware("http")
async def auth_middleware_wrapper(request: Request, call_next):
    request.state.user = None
    request.state.user_type = "guest"
    request.state.new_access_token = None
    request.state.new_refresh_token = None

    log_context = {
        "path": request.url.path,
        "method": request.method,
        "client": request.client.host if request.client else "unknown",
        "user_type": request.state.user_type
    }
    logger.info(f"Incoming request: {request.method} {request.url.path}", extra=log_context)

    response = None
    session = None
    db_session_gen = None # Инициализируем генератор

    try:
        db_session_gen = get_async_session()
        # Используем async for для автоматического закрытия генератора
        async for session in db_session_gen:
            logger.debug("Database session acquired for middleware", extra=log_context)
            try:
                await auth_middleware(request, session)

                log_context["user_type"] = getattr(request.state, "user_type", "guest")
                log_context["user_id"] = getattr(request.state.user, "id", None)

                if request.state.user:
                    logger.info(f"Auth successful: user={log_context['user_id']} ({log_context['user_type']})", extra=log_context)
                # else: # Можно убрать, т.к. middleware auth сам логирует неудачи
                #     logger.info("Request processed without authentication", extra=log_context)

                if request.state.new_access_token:
                    logger.info("Tokens refreshed", extra={**log_context, "token_refresh": True})

                logger.debug("Calling next middleware/endpoint handler", extra=log_context)
                response = await call_next(request)
                logger.debug(f"Endpoint handler finished with status: {response.status_code}", extra=log_context)
                # Выход из цикла, т.к. сессия использована
                break
            finally:
                # Сессия будет закрыта автоматически при выходе из `async for`
                # Но можно добавить лог закрытия здесь, если нужно
                logger.debug("Exiting database session block", extra=log_context)

    # Изменено: Перехватываем HTTPException здесь
    except HTTPException as http_exc:
         log_context["user_type"] = getattr(request.state, "user_type", "error")
         log_context["user_id"] = getattr(request.state.user, "id", "error")
         logger.warning(
             f"HTTP Exception caught in wrapper: {http_exc.status_code} - {http_exc.detail}",
             extra={**log_context, "error": str(http_exc)}
         )
         # Передаем исключение дальше, FastAPI его обработает
         raise http_exc
    except Exception as e:
        log_context["user_type"] = getattr(request.state, "user_type", "error")
        log_context["user_id"] = getattr(request.state.user, "id", "error")
        logger.critical(
            "Unexpected error during request processing",
            exc_info=True,
            extra={**log_context, "error": str(e)}
        )
        # Если response не был создан (ошибка до call_next), создаем 500
        if response is None:
             from fastapi.responses import JSONResponse
             response = JSONResponse(
                 status_code=500,
                 content={"detail": "Internal Server Error"}
             )
        # Если ошибка после call_next, лучше вернуть 500
        else:
             response.status_code = 500
             try:
                 response.body = b'{"detail": "Internal Server Error"}'
                 response.headers['content-length'] = str(len(response.body))
                 response.headers['content-type'] = 'application/json'
             except Exception:
                 pass
    finally:
        # Убедимся, что генератор сессии закрыт, если не был использован `async for` (из-за ошибки до него)
        if db_session_gen and session is None: # session is None значит async for не начался
             try:
                 await db_session_gen.aclose()
                 logger.debug("Database session generator closed (outside async for)", extra=log_context)
             except Exception as gen_close_err:
                 logger.error("Error closing database session generator (outside async for)", exc_info=True, extra={**log_context, "db_error": str(gen_close_err)})
        # Если session не None, async for сам закроет генератор при выходе

    if response is None:
        from fastapi.responses import JSONResponse
        logger.error("Response is None at the end of middleware, returning 500", extra=log_context)
        response = JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error - Response processing failed"}
        )

    # Логируем финальный статус
    final_status = getattr(response, 'status_code', 500) # Получаем статус из response
    logger.info(f"Request finished: {request.method} {request.url.path} - Status: {final_status}", extra=log_context)
    return response


# Middleware для установки токенов в ответы (без изменений)
@application.middleware("http")
async def token_middleware(request: Request, call_next):
    response = await call_next(request)
    new_access_token = getattr(request.state, "new_access_token", None)
    new_refresh_token = getattr(request.state, "new_refresh_token", None)
    user_type = getattr(request.state, "user_type", None)

    if new_access_token and user_type in ["admin", "user"]:
        cookie_key = "admins_access_token" if user_type == "admin" else "users_access_token"
        logger.debug(f"Setting new access token cookie '{cookie_key}'", extra={"path": request.url.path, "user_type": user_type})
        response.set_cookie(key=cookie_key, value=new_access_token, httponly=True, secure=True, samesite="strict")

    if new_refresh_token and user_type in ["admin", "user"]:
        cookie_key = "admins_refresh_token" if user_type == "admin" else "users_refresh_token"
        logger.debug(f"Setting new refresh token cookie '{cookie_key}'", extra={"path": request.url.path, "user_type": user_type})
        response.set_cookie(key=cookie_key, value=new_refresh_token, httponly=True, secure=True, samesite="strict")

    return response


# Подключаем роутеры (без изменений)
application.include_router(admin_auth_router)
application.include_router(user_auth_router)
# ... остальные роутеры ...
application.include_router(debug_router)


# Корневой эндпоинт (без изменений)
@application.get("/")
@limiter.limit("10/minute")
async def root(request: Request):
    return {"message": "Atlas Auth Service is working"}


# Информация о здоровье сервиса (без изменений)
@application.get("/health")
async def health():
    return {"status": "healthy"}


# События startup/shutdown (без изменений)
@application.on_event("startup")
async def startup_event():
    await test_db_connection()
    try:
        await redis_client.ping()
        logger.info("Redis connection successful")
    except Exception as redis_err:
         logger.error(f"❌ Redis cannot connect, startup will be aborted: {redis_err}")
         exit(1)
    logger.info(f"Atlas Auth Service started successfully (DEBUG={config.DEBUG}, ENV={config.ENVIRONMENT})")
    # ... (проверка OAuth) ...

@application.on_event("shutdown")
async def shutdown_event():
    await redis_client.close()
    logger.info("Atlas Auth Service shutdown complete.")