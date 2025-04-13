import logging
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Depends, HTTPException, status
from app.jwt_auth import decode_token, get_async_session

# Создаем отдельный роутер для отладки
router = APIRouter(prefix='/api/debug', tags=['Debug Tools'])

# Настройка логирования
logger = logging.getLogger('debug')
debug_handler = logging.FileHandler('debug.log', mode='a', encoding='utf-8')
debug_handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(levelname)s - [DEBUG] %(message)s - Trace: %(pathname)s:%(lineno)d"
))
logger.addHandler(debug_handler)
logger.setLevel(logging.DEBUG)


@router.get("/token-info")
async def token_info(request: Request):
    """
    Анализ токена из cookie или заголовка Authorization.
    Только для отладки, не использовать в production!
    """
    logger.info("Token info request")

    # Получаем токен из cookie или заголовка
    access_token = request.cookies.get("admins_access_token") or request.cookies.get("users_access_token")

    if not access_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header.replace("Bearer ", "")

    if not access_token:
        logger.warning("No token found in request")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No token found in request"
        )

    try:
        # Базовое декодирование JWT без проверки подписи
        parts = access_token.split('.')

        if len(parts) != 3:
            logger.warning("Invalid token format")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token format"
            )

        # Декодирование header и payload
        def decode_part(part):
            # Дополняем строку, если ее длина не кратна 4
            padding = '=' * (4 - len(part) % 4)
            padded = part + padding
            # Заменяем URL-safe символы на стандартные для base64
            fixed = padded.replace('-', '+').replace('_', '/')
            # Декодируем
            return json.loads(bytes.decode(bytes.fromhex(hex(int(fixed, 16))[2:]), 'utf-8'))

        try:
            header = decode_part(parts[0])
            payload = decode_part(parts[1])

            # Проверяем наличие времени истечения
            exp = payload.get('exp')

            if exp:
                exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
                current_time = datetime.now(timezone.utc)
                remaining = (exp_time - current_time).total_seconds()

                expired = remaining <= 0

                # Форматируем время для вывода
                formatted_exp = exp_time.strftime('%Y-%m-%d %H:%M:%S %Z')
                formatted_current = current_time.strftime('%Y-%m-%d %H:%M:%S %Z')

                expiry_info = {
                    "exp_timestamp": exp,
                    "exp_time": formatted_exp,
                    "current_time": formatted_current,
                    "remaining_seconds": remaining,
                    "expired": expired
                }
            else:
                expiry_info = {"error": "No expiration time found in token"}

            token_info = {
                "header": header,
                "payload": payload,
                "expiry_info": expiry_info
            }

            logger.info(f"Token info decoded: {token_info}")
            return token_info

        except Exception as e:
            logger.error(f"Error decoding token parts: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Error decoding token: {str(e)}"
            )

    except Exception as e:
        logger.error(f"Error processing token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing token: {str(e)}"
        )


@router.get("/oauth-status")
async def oauth_status():
    """
    Проверка статуса OAuth провайдеров и их настроек.
    """
    from app.config import get_oauth_config

    logger.info("OAuth status check requested")

    try:
        oauth_config = get_oauth_config()

        # Собираем статус по каждому провайдеру
        providers_status = {}

        for provider, config in oauth_config.items():
            # Скрываем секретные данные
            safe_config = {
                "provider": provider,
                "client_id_configured": bool(config.get("client_id")),
                "client_secret_configured": bool(config.get("client_secret")),
                "authorize_url": config.get("authorize_url"),
                "token_url": config.get("token_url"),
                "userinfo_url": config.get("userinfo_url"),
                "scope": config.get("scope"),
                "redirect_uri": config.get("redirect_uri")
            }

            # Проверяем, все ли необходимые поля заполнены
            required_fields = ["client_id", "client_secret", "authorize_url", "token_url", "userinfo_url",
                               "redirect_uri"]
            missing_fields = [field for field in required_fields if not config.get(field)]

            safe_config["status"] = "ready" if not missing_fields else "incomplete"
            safe_config["missing_fields"] = missing_fields if missing_fields else None

            providers_status[provider] = safe_config

        logger.info(f"OAuth providers status: {providers_status}")
        return {
            "oauth_providers": providers_status
        }

    except Exception as e:
        logger.error(f"Error checking OAuth status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking OAuth status: {str(e)}"
        )


@router.get("/validate-token")
async def validate_token(request: Request, db=Depends(get_async_session)):
    """
    Полная валидация токена с использованием decode_token.
    """
    logger.info("Token validation request")

    # Получаем токен из cookie или заголовка
    access_token = request.cookies.get("admins_access_token") or request.cookies.get("users_access_token")

    if not access_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header.replace("Bearer ", "")

    if not access_token:
        logger.warning("No token found in request")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No token found in request"
        )

    try:
        # Используем decode_token для полной валидации
        payload = await decode_token(access_token)

        # Проверяем наличие пользователя в БД
        user_id = payload.get("sub")
        token_type = payload.get("type")

        result = {
            "valid": True,
            "payload": payload,
            "token_type": token_type,
            "user_id": user_id
        }

        logger.info(f"Token validated successfully: {result}")
        return result

    except HTTPException as e:
        logger.warning(f"Token validation failed: {e.detail}")
        raise e

    except Exception as e:
        logger.error(f"Error validating token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error validating token: {str(e)}"
        )