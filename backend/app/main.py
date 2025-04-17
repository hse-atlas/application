from fastapi import FastAPI, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from starlette.middleware.sessions import SessionMiddleware
import logging

from app.admin_auth import router as admin_auth_router
from app.user_auth import router as user_auth_router
from app.common_auth import router as common_auth_router
from app.oauth import router as oauth_router
from app.project_CRUD import router as project_crud_router
from app.user_CRUD import router as user_crud_router
from app.user_roles import router as user_roles_router
from app.debug import router as debug_router

from app.database import test_db_connection
# Изменено: Убираем импорт security_config
# from app.security import security_config
# Изменено: Импортируем config напрямую
from app.config import config
from app.jwt_auth import auth_middleware, get_async_session, redis_client # Добавлено: redis_client

# Улучшенная конфигурация логирования (без изменений)
# ... (код логирования) ...
logger = logging.getLogger(__name__)
logger.info("Logging system initialized")

# Создаем лимитер для защиты от DDoS атак (без изменений)
limiter = Limiter(key_func=get_remote_address)

# Создаем приложение FastAPI (без изменений)
application = FastAPI(
    title="Atlas Auth Service",
    description="Микросервис для управления аутентификацией пользователей",
    version="1.0.0",
    debug=config.DEBUG # Используем config.DEBUG
)

# Middleware для обработки сессий (для OAuth)
# Изменено: Используем config.SESSION_SECRET_KEY
application.add_middleware(
    SessionMiddleware,
    secret_key=config.SESSION_SECRET_KEY,
    max_age=1800  # 30 минут
)

# Middleware для CORS
# Изменено: Используем config.CORS_ORIGINS
application.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware для ограничения запросов (без изменений)
application.add_middleware(SlowAPIMiddleware)

# Применение rate limiter к приложению (без изменений)
application.state.limiter = limiter


# Обработчик ошибок для превышения лимита запросов (без изменений)
@application.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc):
    from fastapi.responses import JSONResponse
    logger.warning(f"Rate limit exceeded for {get_remote_address(request)}")
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"}
    )


# Изменено: Middleware аутентификации - немного доработаны логи и инициализация state
@application.middleware("http")
async def auth_middleware_wrapper(request: Request, call_next):
    # Инициализация состояния перед вызовом auth_middleware
    request.state.user = None
    request.state.user_type = "guest"
    request.state.new_access_token = None
    request.state.new_refresh_token = None

    log_context = {
        "path": request.url.path,
        "method": request.method,
        "client": request.client.host if request.client else "unknown",
        "user_type": request.state.user_type # Начальное значение
    }
    logger.info(f"Incoming request: {request.method} {request.url.path}", extra=log_context)

    response = None # Инициализация response
    session = None # Инициализация session

    try:
        # Получаем сессию БД
        db_session_gen = get_async_session()
        session = await anext(db_session_gen) # Получаем сессию
        logger.debug("Database session acquired for middleware", extra=log_context)

        # Выполняем основную логику аутентификации
        # auth_middleware теперь сам установит user и user_type в request.state при успехе
        await auth_middleware(request, session)

        # Обновляем user_type в логах после auth_middleware
        log_context["user_type"] = getattr(request.state, "user_type", "guest") # Получаем актуальный тип
        log_context["user_id"] = getattr(request.state.user, "id", None) # Добавляем ID если есть

        if request.state.user:
            logger.info(f"Authentication successful for user {log_context['user_id']} ({log_context['user_type']})", extra=log_context)
        else:
             logger.info("Request processed without authentication (public route or failed auth handled internally)", extra=log_context)

        # Логируем обновление токенов (если оно произошло)
        if request.state.new_access_token:
            logger.info("Tokens refreshed (via sliding window or refresh endpoint)", extra={**log_context, "token_refresh": True})

        # Выполняем обработку самого запроса (вызов эндпоинта)
        logger.debug("Calling next middleware/endpoint handler", extra=log_context)
        response = await call_next(request)
        logger.debug(f"Endpoint handler finished with status: {response.status_code}", extra=log_context)

    except HTTPException as http_exc:
         # Логируем HTTP исключения, которые дошли до этого уровня
         log_context["user_type"] = getattr(request.state, "user_type", "error")
         log_context["user_id"] = getattr(request.state.user, "id", "error")
         logger.warning(
             f"HTTP Exception during request processing: {http_exc.status_code} - {http_exc.detail}",
             extra={**log_context, "error": str(http_exc)}
         )
         # Пересоздаем response, т.к. call_next не был вызван или прерван
         # FastAPI сам обработает это исключение и вернет клиенту
         raise http_exc
    except Exception as e:
        # Логируем любые другие неожиданные ошибки
        log_context["user_type"] = getattr(request.state, "user_type", "error")
        log_context["user_id"] = getattr(request.state.user, "id", "error")
        logger.critical(
            "Unexpected error during request processing",
            exc_info=True, # Включаем traceback для критических ошибок
            extra={**log_context, "error": str(e)}
        )
        # Возвращаем стандартный 500 Internal Server Error
        # Если response не был создан, создаем его
        if response is None:
             from fastapi.responses import JSONResponse
             response = JSONResponse(
                 status_code=500,
                 content={"detail": "Internal Server Error"}
             )
        else:
             # Если response был создан, но ошибка произошла после,
             # лучше вернуть 500, чтобы не отправлять потенциально некорректный ответ
             response.status_code = 500
             try:
                 # Попытка установить тело ответа, если возможно
                 response.body = b'{"detail": "Internal Server Error"}'
                 response.headers['content-length'] = str(len(response.body))
                 response.headers['content-type'] = 'application/json'
             except Exception: # Если изменить response нельзя, просто возвращаем его
                 pass
    finally:
        # Закрываем сессию БД, если она была открыта
        if session:
            try:
                await session.close()
                logger.debug("Database session closed", extra=log_context)
            except Exception as db_close_err:
                 logger.error("Error closing database session", exc_info=True, extra={**log_context, "db_error": str(db_close_err)})
        # Если генератор не был полностью использован (из-за ошибки до `anext`)
        elif 'db_session_gen' in locals() and db_session_gen:
             try:
                 await db_session_gen.aclose() # Используем aclose для async generator
                 logger.debug("Database session generator closed", extra=log_context)
             except Exception as gen_close_err:
                 logger.error("Error closing database session generator", exc_info=True, extra={**log_context, "db_error": str(gen_close_err)})


    # Убедимся, что response всегда возвращается
    if response is None:
        # Этого не должно произойти при нормальной работе или обработке ошибок выше,
        # но на всякий случай вернем 500
        from fastapi.responses import JSONResponse
        logger.error("Response object is None at the end of middleware, returning 500", extra=log_context)
        response = JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error - Response processing failed"}
        )

    logger.info(f"Request finished: {request.method} {request.url.path} - Status: {response.status_code}", extra=log_context)
    return response


# Middleware для установки токенов в ответы (без изменений)
@application.middleware("http")
async def token_middleware(request: Request, call_next):
    # Запуск эндпоинта
    response = await call_next(request)

    # Проверяем наличие новых токенов в request.state (установленных auth_middleware или /refresh)
    # Используем getattr для безопасного доступа
    new_access_token = getattr(request.state, "new_access_token", None)
    new_refresh_token = getattr(request.state, "new_refresh_token", None)
    user_type = getattr(request.state, "user_type", None) # Получаем тип пользователя из state

    if new_access_token and user_type:
        cookie_key = "admins_access_token" if user_type == "admin" else "users_access_token"
        logger.debug(f"Setting new access token cookie '{cookie_key}' in response",
                     extra={"path": request.url.path, "user_type": user_type})
        response.set_cookie(
            key=cookie_key,
            value=new_access_token,
            httponly=True,
            secure=True, # Включать в production
            samesite="strict"
        )

    if new_refresh_token and user_type:
        cookie_key = "admins_refresh_token" if user_type == "admin" else "users_refresh_token"
        logger.debug(f"Setting new refresh token cookie '{cookie_key}' in response",
                     extra={"path": request.url.path, "user_type": user_type})
        response.set_cookie(
            key=cookie_key,
            value=new_refresh_token,
            httponly=True,
            secure=True, # Включать в production
            samesite="strict"
        )

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


# События при запуске и остановке приложения
@application.on_event("startup")
async def startup_event():
    # Тестируем подключение к базе данных
    await test_db_connection()
    # Добавлено: Тестируем подключение к Redis
    try:
        await redis_client.ping()
        logger.info("Redis connection successful")
    except Exception as redis_err:
         logger.error(f"❌ Redis cannot connect, startup will be aborted: {redis_err}")
         exit(1)

    # Добавляем информацию о запуске в логи
    logger.info(f"Atlas Auth Service started successfully (DEBUG={config.DEBUG}, ENV={config.ENVIRONMENT})")

    # Проверяем настройки OAuth и логируем их статус
    from app.config import get_oauth_config
    oauth_config = get_oauth_config()
    oauth_status = {}
    for provider, cfg in oauth_config.items():
        client_configured = bool(cfg.get("client_id")) and bool(cfg.get("client_secret"))
        oauth_status[provider] = "configured" if client_configured else "NOT CONFIGURED"
    logger.info(f"OAuth providers status on startup: {oauth_status}")


@application.on_event("shutdown")
async def shutdown_event():
    # Закрываем соединение с Redis
    await redis_client.close()
    # Логируем остановку сервиса
    logger.info("Atlas Auth Service shutdown complete.")