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

from app.database import test_db_connection
from app.security import security_config
from app.jwt_auth import auth_middleware, get_async_session


# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app.log")
    ]
)
logger = logging.getLogger(__name__)

# Создаем лимитер для защиты от DDoS атак
limiter = Limiter(key_func=get_remote_address)

# Создаем приложение FastAPI
application = FastAPI(
    title="Atlas Auth Service",
    description="Микросервис для управления аутентификацией пользователей",
    version="1.0.0",
    debug=False  # В продакшене лучше выключить режим отладки
)

# Middleware для обработки сессий (для OAuth)
application.add_middleware(
    SessionMiddleware,
    secret_key=security_config.SESSION_SECRET_KEY,
    max_age=1800  # 30 минут
)

# Middleware для CORS
application.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware для ограничения запросов
application.add_middleware(SlowAPIMiddleware)

# Применение rate limiter к приложению
application.state.limiter = limiter


# Обработчик ошибок для превышения лимита запросов
@application.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc):
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."}
    )


@application.middleware("http")
async def auth_middleware_wrapper(request: Request, call_next):
    # Явная инициализация состояния
    request.state.user_type = "guest"  # <-- Ключевое исправление
    request.state.new_access_token = None
    request.state.new_refresh_token = None

    # Инициализация логов для запроса
    log_context = {
        "path": request.url.path,
        "method": request.method,
        "client": request.client.host if request.client else "unknown",
        "user_type": request.state.user_type  # Добавляем в логи
    }

    logger.info("Starting authentication middleware", extra=log_context)

    try:
        # Получаем сессию БД с логированием
        logger.debug("Acquiring database session")
        db = get_async_session()

        async for session in db:
            try:
                logger.debug("Database session acquired", extra=log_context)

                # Обновляем user_type в логах
                log_context["user_type"] = request.state.user_type

                # Логируем начало обработки
                logger.debug("Executing auth middleware logic", extra=log_context)

                # Выполняем основную логику
                result = await auth_middleware(request, session)

                # Обновляем логи после обработки
                log_context["user_type"] = request.state.user_type

                # Логируем успешное завершение
                if result:
                    logger.info("Authentication successful", extra=log_context)

                # Логируем новую информацию о токенах (для "скользящего окна")
                if hasattr(request.state, "new_access_token") and request.state.new_access_token:
                    logger.info("Tokens refreshed using sliding window mechanism", extra={
                        **log_context,
                        "token_refresh": True
                    })

            except Exception as e:
                # Фиксируем текущий user_type при ошибке
                log_context["user_type"] = getattr(request.state, "user_type", "error")
                logger.error("Auth middleware processing failed",
                             exc_info=True,
                             extra={**log_context, "error": str(e)})
                raise

            finally:
                logger.debug("Releasing database session", extra=log_context)

    except Exception as e:
        # Фиксируем финальный user_type
        log_context["user_type"] = getattr(request.state, "user_type", "error")
        logger.critical("Authentication middleware failed",
                        exc_info=True,
                        extra={**log_context, "error": str(e)})
        raise

    # Фиксируем итоговый статус
    log_context["user_type"] = request.state.user_type
    logger.info("Authentication middleware completed", extra=log_context)

    # Выполняем обработку запроса
    response = await call_next(request)

    return response


# Middleware для установки токенов в ответы
@application.middleware("http")
async def token_middleware(request: Request, call_next):
    # Запуск эндпоинта
    response = await call_next(request)

    # Проверяем наличие новых токенов в request.state
    if hasattr(request.state, "new_access_token") and request.state.new_access_token:
        logger.debug("Setting new access token in response",
                     extra={"path": request.url.path, "user_type": request.state.user_type})

        # Устанавливаем новый access token
        response.set_cookie(
            key=(
                "admins_access_token"
                if request.state.user_type == "admin"
                else "users_access_token"
            ),
            value=request.state.new_access_token,
            httponly=True,
            secure=True,
            samesite="strict"
        )

    if hasattr(request.state, "new_refresh_token") and request.state.new_refresh_token:
        logger.debug("Setting new refresh token in response",
                     extra={"path": request.url.path, "user_type": request.state.user_type})

        # Устанавливаем новый refresh token
        response.set_cookie(
            key=(
                "admins_refresh_token"
                if request.state.user_type == "admin"
                else "users_refresh_token"
            ),
            value=request.state.new_refresh_token,
            httponly=True,
            secure=True,
            samesite="strict"
        )

    return response


# Подключаем роутеры
application.include_router(admin_auth_router)
application.include_router(user_auth_router)
application.include_router(common_auth_router)
application.include_router(oauth_router)
application.include_router(project_crud_router)
application.include_router(user_crud_router)
application.include_router(user_roles_router)


# Корневой эндпоинт
@application.get("/")
@limiter.limit("10/minute")
async def root(request: Request):
    return {"message": "Atlas Auth Service is working"}


# Информация о здоровье сервиса
@application.get("/health")
async def health():
    return {"status": "healthy"}


# События при запуске и остановке приложения
@application.on_event("startup")
async def startup_event():
    # Тестируем подключение к базе данных
    await test_db_connection()

    # Добавляем информацию о запуске в логи
    logger.info("Atlas Auth Service started successfully")


@application.on_event("shutdown")
async def shutdown_event():
    # Логируем остановку сервиса
    logger.info("Atlas Auth Service shutdown")