import logging
import re # <-- Добавлен импорт re
from asyncio import anext # <-- Убедитесь, что это не вызовет ImportError на Python < 3.10

from fastapi import FastAPI, Depends, Request, Response, HTTPException, status # Добавлен status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse # <-- Добавлен JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from starlette.middleware.sessions import SessionMiddleware

# Импорт роутеров
from app.admin_auth import router as admin_auth_router
from app.user_auth import router as user_auth_router
from app.common_auth import router as common_auth_router
from app.oauth import router as oauth_router
from app.project_CRUD import router as project_crud_router
from app.user_CRUD import router as user_crud_router
from app.user_roles import router as user_roles_router
from app.debug import router as debug_router

# Импорт конфигурации и вспомогательных функций
from app.database import test_db_connection
from app.config import config # Используем config напрямую
from app.jwt_auth import auth_middleware, get_async_session, redis_client

# --- Настройка логирования ---
logging.basicConfig(
    level=logging.INFO if config.ENVIRONMENT != "development" else logging.DEBUG, # DEBUG в разработке
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s - Trace: %(pathname)s:%(lineno)d",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app.log", mode='a', encoding='utf-8')
    ]
)
# Настройка логгеров для auth, oauth, error, debug, cookie_setter (если используется)
# ... (ваш код настройки логгеров) ...
logger = logging.getLogger(__name__)
logger.info("Logging system initialized")
# --- Конец настройки логирования ---


# --- Список публичных путей (используем регулярные выражения) ---
PUBLIC_PATHS_PATTERNS = [
    re.compile(r"^/$"),                                         # Корень
    re.compile(r"^/health$"),                                   # Статус
    re.compile(r"^/docs$"),                                     # Swagger UI
    re.compile(r"^/openapi\.json$"),                           # OpenAPI схема
    re.compile(r"^/favicon\.ico$"),                            # Favicon
    re.compile(r"^/static/.*$"),                               # Статические файлы (если есть)
    re.compile(r"^/api/auth/admin/login/$"),                   # Вход админа
    re.compile(r"^/api/auth/admin/register/$"),                # Регистрация админа
    re.compile(r"^/api/auth/user/login/.*$"),                  # Вход пользователя (с project_id)
    re.compile(r"^/api/auth/user/register/.*$"),               # Регистрация пользователя (с project_id)
    # re.compile(r"^/api/auth/refresh/$"),                      # Обновление - требует ли валидный access? Обычно нет.
    re.compile(r"^/api/auth/oauth/.*$"),                       # Весь процесс OAuth
    re.compile(r"^/api/projects/[0-9a-fA-F-]+/oauth-config$"), # Публичный конфиг OAuth проекта
    re.compile(r"^/embed/.*$"),                                # Встраиваемые формы
]

# --- Создание приложения FastAPI ---
application = FastAPI(
    title=config.APP_NAME,
    description="Микросервис для управления аутентификацией пользователей",
    version=config.APP_VERSION,
    debug=config.DEBUG
)

# --- Middleware ---

# 1. Обработка ошибок (должен быть одним из первых)
#    FastAPI/Starlette имеют встроенный, но можно кастомизировать

# 2. CORS
application.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True, # Важно для сессий OAuth
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Сессии (нужны для OAuth state)
application.add_middleware(
    SessionMiddleware,
    secret_key=config.SESSION_SECRET_KEY,
    https_only=config.ENVIRONMENT != "development", # secure=True в production
    max_age=1800 # 30 минут для state
)

# 4. Rate Limiter (SlowAPI)
limiter = Limiter(key_func=get_remote_address)
application.state.limiter = limiter
application.add_middleware(SlowAPIMiddleware)
# Обработчик ошибок для Rate Limiter
application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# 5. Middleware Аутентификации (главный)
@application.middleware("http")
async def auth_middleware_wrapper(request: Request, call_next):
    path = request.url.path
    is_public = any(pattern.match(path) for pattern in PUBLIC_PATHS_PATTERNS)

    log_context = {
        "path": path,
        "method": request.method,
        "client": request.client.host if request.client else "unknown",
        "is_public": is_public
    }
    logger.info(f"Incoming request: {request.method} {path}", extra=log_context)

    # Инициализация state
    request.state.user = None
    request.state.user_type = "guest"
    request.state.new_access_token = None # Для скользящего окна
    request.state.new_refresh_token = None # Для скользящего окна

    # Если путь публичный, пропускаем всю логику аутентификации
    if is_public:
        logger.debug(f"Public path '{path}', skipping auth middleware logic.")
        response = await call_next(request)
        logger.info(f"Request finished (public): {request.method} {path} - Status: {response.status_code}", extra=log_context)
        return response

    # --- Логика для ЗАЩИЩЕННЫХ путей ---
    response = None
    session = None
    db_session_gen = None
    authenticated_user = None # Храним результат auth_middleware

    try:
        db_session_gen = get_async_session()
        async for session in db_session_gen:
            logger.debug("Database session acquired for auth middleware", extra=log_context)
            try:
                # Выполняем основную логику аутентификации из jwt_auth.py
                # Она вернет user или выбросит HTTPException
                authenticated_user = await auth_middleware(request, session)

                # auth_middleware должен сам выбросить 401/403, если аутентификация не удалась
                # Проверка authenticated_user здесь больше для полноты картины
                if not authenticated_user:
                     # Этого не должно происходить, если auth_middleware реализован правильно
                     logger.error("Auth middleware returned None for a protected route! Denying access.", extra=log_context)
                     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed unexpectedly")

                # Логируем успех (user и user_type уже установлены в request.state внутри auth_middleware)
                log_context["user_type"] = getattr(request.state, "user_type", "error")
                log_context["user_id"] = getattr(request.state.user, "id", "error")
                logger.info(f"Auth successful: user={log_context['user_id']} ({log_context['user_type']})", extra=log_context)

                # Проверяем, обновились ли токены скользящим окном
                if request.state.new_access_token:
                    logger.info("Tokens potentially refreshed by sliding window (will be handled by client)", extra={**log_context, "token_refresh": True})

                # Вызываем следующий обработчик/эндпоинт
                logger.debug("Calling next middleware/endpoint handler", extra=log_context)
                response = await call_next(request)
                logger.debug(f"Endpoint handler finished with status: {response.status_code}", extra=log_context)
                break # Выход из цикла после успешной обработки
            finally:
                logger.debug("Exiting database session block (inside async for)", extra=log_context)

    except HTTPException as http_exc:
         # Ловим ошибки аутентификации (401, 403) из auth_middleware или другие HTTP ошибки
         log_context["user_type"] = getattr(request.state, "user_type", "error") # Попытка получить тип
         log_context["user_id"] = getattr(request.state.user, "id", "error") # Попытка получить ID
         logger.warning(
             f"HTTP Exception caught in auth wrapper: {http_exc.status_code} - {http_exc.detail}",
             extra={**log_context, "error_detail": http_exc.detail}
         )
         # Передаем исключение дальше, FastAPI его обработает
         raise http_exc
    except Exception as e:
        # Ловим любые другие неожиданные ошибки
        log_context["user_type"] = getattr(request.state, "user_type", "error")
        log_context["user_id"] = getattr(request.state.user, "id", "error")
        logger.critical(
            "Unexpected error during authenticated request processing",
            exc_info=True,
            extra={**log_context, "error": str(e)}
        )
        # Возвращаем 500, если response еще не был создан
        if response is None:
             response = JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
        else: # Если ошибка после call_next, меняем статус существующего ответа
             response.status_code = 500
             try:
                 response.body = b'{"detail": "Internal Server Error"}'
                 response.headers['content-length'] = str(len(response.body))
                 response.headers['content-type'] = 'application/json'
             except Exception: pass # Игнорируем ошибки изменения ответа
    finally:
        # Закрываем генератор сессии, если он не был полностью использован
        if db_session_gen and session is None:
             try:
                 await db_session_gen.aclose()
                 logger.debug("Database session generator closed (outside async for)", extra=log_context)
             except Exception as gen_close_err:
                 logger.error("Error closing database session generator", exc_info=True, extra={**log_context, "db_error": str(gen_close_err)})
        logger.debug("Finished auth middleware wrapper processing.", extra=log_context)

    # Убедимся, что response всегда есть
    if response is None:
        logger.error("Response object is None at the end of auth wrapper, returning 500", extra=log_context)
        response = JSONResponse(status_code=500, content={"detail": "Internal Server Error - Response processing failed"})

    final_status = getattr(response, 'status_code', 500)
    logger.info(f"Request finished (authenticated): {request.method} {path} - Status: {final_status}", extra=log_context)
    return response

# --- Middleware для установки токенов УДАЛЕН ---

# --- Подключение роутеров ---
application.include_router(admin_auth_router)
application.include_router(user_auth_router)
application.include_router(common_auth_router)
application.include_router(oauth_router)
application.include_router(project_crud_router)
application.include_router(user_crud_router)
application.include_router(user_roles_router)
application.include_router(debug_router)


# --- Корневые эндпоинты и события ---
@application.get("/")
async def root():
    return {"message": f"{config.APP_NAME} is working"}

@application.get("/health")
async def health():
    # Можно добавить проверки БД и Redis здесь
    return {"status": "healthy"}

@application.on_event("startup")
async def startup_event():
    await test_db_connection()
    try:
        await redis_client.ping()
        logger.info("Redis connection successful")
    except Exception as redis_err:
         logger.error(f"❌ Redis connection failed: {redis_err}", exc_info=True)
         # exit(1) # Можно раскомментировать для остановки при ошибке Redis
    logger.info(f"{config.APP_NAME} started (Version: {config.APP_VERSION}, Environment: {config.ENVIRONMENT}, Debug: {config.DEBUG})")
    # Проверка OAuth статуса
    oauth_config = get_oauth_config()
    oauth_status = {p: "configured" if (cfg.get("client_id") and cfg.get("client_secret")) else "NOT CONFIGURED" for p, cfg in oauth_config.items()}
    logger.info(f"OAuth providers status: {oauth_status}")

@application.on_event("shutdown")
async def shutdown_event():
    await redis_client.close()
    logger.info(f"{config.APP_NAME} shutdown complete.")