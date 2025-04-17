from fastapi import FastAPI, Depends, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from starlette.middleware.sessions import SessionMiddleware
import logging
# Изменено: Убираем импорт anext
# from asyncio import anext

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
    db_session_gen = None

    try:
        db_session_gen = get_async_session()
        # Изменено: Используем стандартный async for для итерации по генератору сессии
        async for session in db_session_gen:
            logger.debug("Database session acquired for middleware", extra=log_context)
            try:
                # Выполняем основную логику аутентификации
                await auth_middleware(request, session)

                # Обновляем user_type и user_id в логах после auth_middleware
                log_context["user_type"] = getattr(request.state, "user_type", "guest")
                log_context["user_id"] = getattr(request.state.user, "id", None)

                if request.state.user:
                    logger.info(f"Auth successful: user={log_context['user_id']} ({log_context['user_type']})", extra=log_context)

                if request.state.new_access_token:
                    logger.info("Tokens refreshed", extra={**log_context, "token_refresh": True})

                # Выполняем обработку самого запроса
                logger.debug("Calling next middleware/endpoint handler", extra=log_context)
                response = await call_next(request)
                logger.debug(f"Endpoint handler finished with status: {response.status_code}", extra=log_context)
                # Выход из цикла и генератора после успешной обработки
                break
            finally:
                # Блок finally внутри async for выполнится перед закрытием генератора
                logger.debug("Exiting database session block (inside async for)", extra=log_context)
                # Нет необходимости вручную закрывать session здесь, async for сделает это

    except HTTPException as http_exc:
         log_context["user_type"] = getattr(request.state, "user_type", "error")
         log_context["user_id"] = getattr(request.state.user, "id", "error")
         logger.warning(
             f"HTTP Exception caught in wrapper: {http_exc.status_code} - {http_exc.detail}",
             extra={**log_context, "error": str(http_exc)}
         )
         raise http_exc
    except Exception as e:
        log_context["user_type"] = getattr(request.state, "user_type", "error")
        log_context["user_id"] = getattr(request.state.user, "id", "error")
        logger.critical(
            "Unexpected error during request processing",
            exc_info=True,
            extra={**log_context, "error": str(e)}
        )
        if response is None:
             from fastapi.responses import JSONResponse
             response = JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
        else:
             response.status_code = 500
             try:
                 response.body = b'{"detail": "Internal Server Error"}'
                 response.headers['content-length'] = str(len(response.body))
                 response.headers['content-type'] = 'application/json'
             except Exception: pass
    finally:
        # `async for` автоматически закроет генератор `db_session_gen`
        # при нормальном выходе или при возникновении исключения *внутри* цикла.
        # Ручное закрытие не требуется.
        logger.debug("Async for database session generator finished or exited.", extra=log_context)


    if response is None:
        from fastapi.responses import JSONResponse
        logger.error("Response is None at the end of middleware, returning 500", extra=log_context)
        response = JSONResponse(status_code=500, content={"detail": "Internal Server Error - Response processing failed"})

    final_status = getattr(response, 'status_code', 500)
    logger.info(f"Request finished: {request.method} {request.url.path} - Status: {final_status}", extra=log_context)
    return response


# Подключаем роутеры (без изменений)
application.include_router(admin_auth_router)
application.include_router(user_auth_router)
application.include_router(common_auth_router)
application.include_router(oauth_router)
application.include_router(project_crud_router)
application.include_router(user_crud_router)
application.include_router(user_roles_router)
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
    # ... (проверки БД и Redis) ...
    logger.info(f"Atlas Auth Service started successfully (DEBUG={config.DEBUG}, ENV={config.ENVIRONMENT})")
    # ... (проверка OAuth) ...

@application.on_event("shutdown")
async def shutdown_event():
    await redis_client.close()
    logger.info("Atlas Auth Service shutdown complete.")