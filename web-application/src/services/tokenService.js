// tokenService.js - единый сервис для управления токенами

const TOKEN_NAMES = {
  ADMIN_ACCESS: {
    cookie: "admins_access_token",
    storage: "admin_access_token"
  },
  ADMIN_REFRESH: {
    cookie: "admins_refresh_token",
    storage: "admin_refresh_token"
  },
  USER_ACCESS: {
    cookie: "users_access_token",
    storage: "user_access_token"
  },
  USER_REFRESH: {
    cookie: "users_refresh_token",
    storage: "user_refresh_token"
  }
};

/**
 * Получает токен из cookie
 * @param {string} name - имя cookie
 * @returns {string|null} - значение токена или null
 */
function getTokenFromCookie(name) {
  const cookies = document.cookie.split(';');
  for (let cookie of cookies) {
    const [cookieName, cookieValue] = cookie.trim().split('=');
    if (cookieName === name) {
      return cookieValue;
    }
  }
  return null;
}

/**
 * Декодирует JWT токен без проверки подписи
 * @param {string} token - JWT токен
 * @returns {Object|null} - декодированный payload или null при ошибке
 */
function decodeToken(token) {
  if (!token) return null;

  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64).split('').map(c => {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join('')
    );

    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error('Error decoding token:', error);
    return null;
  }
}

/**
 * Получает тип пользователя из токена
 * @returns {string|null} - тип пользователя ('admin' или 'user') или null
 */
function getUserTypeFromToken() {
  const token = getAccessToken();
  if (!token) return null;

  const decoded = decodeToken(token);
  return decoded?.user_type || null;
}

/**
 * Получает тип пользователя
 * @returns {string|null} - тип пользователя ('admin' или 'user') или null
 */
function getUserType() {
  return getUserTypeFromToken();
}

/**
 * Синхронизирует токены в localStorage и определяет их тип
 */
function synchronizeTokens() {
  // Сначала пытаемся определить тип пользователя из токена
  const userType = getUserTypeFromToken();
  console.debug(`Synchronizing tokens. User type from token: ${userType}`);

  if (!userType) {
    console.debug('No user type determined from token, cannot synchronize tokens properly');
    return;
  }

  if (userType === 'admin') {
    // Для админа берем соответствующие куки
    const accessTokenCookie = getTokenFromCookie(TOKEN_NAMES.ADMIN_ACCESS.cookie);
    const refreshTokenCookie = getTokenFromCookie(TOKEN_NAMES.ADMIN_REFRESH.cookie);

    if (accessTokenCookie) {
      localStorage.setItem(TOKEN_NAMES.ADMIN_ACCESS.storage, accessTokenCookie);
    }

    if (refreshTokenCookie) {
      localStorage.setItem(TOKEN_NAMES.ADMIN_REFRESH.storage, refreshTokenCookie);
    }

    // Очищаем пользовательские токены если они есть
    localStorage.removeItem(TOKEN_NAMES.USER_ACCESS.storage);
    localStorage.removeItem(TOKEN_NAMES.USER_REFRESH.storage);
  } else if (userType === 'user') {
    // Для обычного пользователя берем соответствующие куки
    const accessTokenCookie = getTokenFromCookie(TOKEN_NAMES.USER_ACCESS.cookie);
    const refreshTokenCookie = getTokenFromCookie(TOKEN_NAMES.USER_REFRESH.cookie);

    if (accessTokenCookie) {
      localStorage.setItem(TOKEN_NAMES.USER_ACCESS.storage, accessTokenCookie);
    }

    if (refreshTokenCookie) {
      localStorage.setItem(TOKEN_NAMES.USER_REFRESH.storage, refreshTokenCookie);
    }

    // Очищаем админские токены если они есть
    localStorage.removeItem(TOKEN_NAMES.ADMIN_ACCESS.storage);
    localStorage.removeItem(TOKEN_NAMES.ADMIN_REFRESH.storage);
  }
}

/**
 * Получает актуальный access токен с предварительной синхронизацией
 * @returns {string|null} - актуальный access токен или null
 */
function getAccessToken() {
  // Определяем тип токена из локального хранилища
  // Проверяем сначала оба типа токенов - если есть админский, используем его, иначе пользовательский
  const adminToken = localStorage.getItem(TOKEN_NAMES.ADMIN_ACCESS.storage);
  if (adminToken) {
    return adminToken;
  }

  const userToken = localStorage.getItem(TOKEN_NAMES.USER_ACCESS.storage);
  if (userToken) {
    return userToken;
  }

  // Если нет токенов в localStorage, проверяем cookies
  const adminCookieToken = getTokenFromCookie(TOKEN_NAMES.ADMIN_ACCESS.cookie);
  if (adminCookieToken) {
    // Синхронизируем с localStorage
    localStorage.setItem(TOKEN_NAMES.ADMIN_ACCESS.storage, adminCookieToken);
    return adminCookieToken;
  }

  const userCookieToken = getTokenFromCookie(TOKEN_NAMES.USER_ACCESS.cookie);
  if (userCookieToken) {
    // Синхронизируем с localStorage
    localStorage.setItem(TOKEN_NAMES.USER_ACCESS.storage, userCookieToken);
    return userCookieToken;
  }

  return null;
}

/**
 * Получает актуальный refresh токен с предварительной синхронизацией
 * @returns {string|null} - актуальный refresh токен или null
 */
function getRefreshToken() {
  // Определяем тип токена по типу пользователя из текущего access токена
  const userType = getUserTypeFromToken();

  if (!userType) {
    // Если не можем определить тип из токена, проверяем наличие обоих типов рефреш токенов
    const adminRefreshToken = localStorage.getItem(TOKEN_NAMES.ADMIN_REFRESH.storage) ||
                              getTokenFromCookie(TOKEN_NAMES.ADMIN_REFRESH.cookie);

    if (adminRefreshToken) {
      // Синхронизируем с localStorage если токен из cookie
      if (getTokenFromCookie(TOKEN_NAMES.ADMIN_REFRESH.cookie) === adminRefreshToken) {
        localStorage.setItem(TOKEN_NAMES.ADMIN_REFRESH.storage, adminRefreshToken);
      }
      return adminRefreshToken;
    }

    const userRefreshToken = localStorage.getItem(TOKEN_NAMES.USER_REFRESH.storage) ||
                             getTokenFromCookie(TOKEN_NAMES.USER_REFRESH.cookie);

    if (userRefreshToken) {
      // Синхронизируем с localStorage если токен из cookie
      if (getTokenFromCookie(TOKEN_NAMES.USER_REFRESH.cookie) === userRefreshToken) {
        localStorage.setItem(TOKEN_NAMES.USER_REFRESH.storage, userRefreshToken);
      }
      return userRefreshToken;
    }

    return null;
  }

  // Если тип известен, выбираем соответствующий токен
  if (userType === 'admin') {
    const adminRefreshToken = localStorage.getItem(TOKEN_NAMES.ADMIN_REFRESH.storage) ||
                              getTokenFromCookie(TOKEN_NAMES.ADMIN_REFRESH.cookie);

    if (adminRefreshToken && getTokenFromCookie(TOKEN_NAMES.ADMIN_REFRESH.cookie) === adminRefreshToken) {
      localStorage.setItem(TOKEN_NAMES.ADMIN_REFRESH.storage, adminRefreshToken);
    }

    return adminRefreshToken;
  } else {
    const userRefreshToken = localStorage.getItem(TOKEN_NAMES.USER_REFRESH.storage) ||
                             getTokenFromCookie(TOKEN_NAMES.USER_REFRESH.cookie);

    if (userRefreshToken && getTokenFromCookie(TOKEN_NAMES.USER_REFRESH.cookie) === userRefreshToken) {
      localStorage.setItem(TOKEN_NAMES.USER_REFRESH.storage, userRefreshToken);
    }

    return userRefreshToken;
  }
}

/**
 * Сохраняет токены в localStorage и в cookies
 * @param {Object} tokens - объект с токенами {access_token, refresh_token}
 */
function saveTokens(tokens) {
  if (!tokens) return;

  const { access_token, refresh_token } = tokens;

  // Определяем тип пользователя из токена
  const decoded = access_token ? decodeToken(access_token) : null;
  const userType = decoded?.user_type;

  if (!userType) {
    console.error("Cannot save tokens: user_type not found in token");
    return;
  }

  console.log(`Saving tokens for user type: ${userType}`);

  // Определяем правильные ключи на основе типа пользователя из токена
  const accessStorageKey = userType === 'admin' ?
    TOKEN_NAMES.ADMIN_ACCESS.storage : TOKEN_NAMES.USER_ACCESS.storage;

  const refreshStorageKey = userType === 'admin' ?
    TOKEN_NAMES.ADMIN_REFRESH.storage : TOKEN_NAMES.USER_REFRESH.storage;

  const accessCookieName = userType === 'admin' ?
    TOKEN_NAMES.ADMIN_ACCESS.cookie : TOKEN_NAMES.USER_ACCESS.cookie;

  const refreshCookieName = userType === 'admin' ?
    TOKEN_NAMES.ADMIN_REFRESH.cookie : TOKEN_NAMES.USER_REFRESH.cookie;

  // Сохраняем в localStorage
  if (access_token) {
    localStorage.setItem(accessStorageKey, access_token);
  }

  if (refresh_token) {
    localStorage.setItem(refreshStorageKey, refresh_token);
  }

  // Сохраняем в cookies только если их нет или они отличаются
  if (access_token && getTokenFromCookie(accessCookieName) !== access_token) {
    document.cookie = `${accessCookieName}=${access_token}; path=/; secure; samesite=strict`;
  }

  if (refresh_token && getTokenFromCookie(refreshCookieName) !== refresh_token) {
    document.cookie = `${refreshCookieName}=${refresh_token}; path=/; secure; samesite=strict`;
  }
}

/**
 * Удаляет все токены из localStorage и cookies
 */
function clearTokens() {
  // Очищаем localStorage
  localStorage.removeItem(TOKEN_NAMES.ADMIN_ACCESS.storage);
  localStorage.removeItem(TOKEN_NAMES.ADMIN_REFRESH.storage);
  localStorage.removeItem(TOKEN_NAMES.USER_ACCESS.storage);
  localStorage.removeItem(TOKEN_NAMES.USER_REFRESH.storage);

  // Очищаем cookies
  const pastDate = new Date(0).toUTCString();
  document.cookie = `${TOKEN_NAMES.ADMIN_ACCESS.cookie}=; expires=${pastDate}; path=/;`;
  document.cookie = `${TOKEN_NAMES.ADMIN_REFRESH.cookie}=; expires=${pastDate}; path=/;`;
  document.cookie = `${TOKEN_NAMES.USER_ACCESS.cookie}=; expires=${pastDate}; path=/;`;
  document.cookie = `${TOKEN_NAMES.USER_REFRESH.cookie}=; expires=${pastDate}; path=/;`;
}

/**
* Проверяет, авторизован ли пользователь
* @returns {boolean} - true, если пользователь авторизован
*/
function isAuthenticated() {
  return !!getAccessToken();
}

/**
* Определяет URL для обновления токена на основе типа пользователя и проекта
* @param {string|null} projectId - ID проекта (только для пользователей)
* @returns {string} - URL для обновления токена
*/
function getRefreshEndpoint(projectId = null) {
  const userType = getUserType();

  if (userType === 'admin') {
    return "/api/auth/admin/refresh/";
  } else if (userType === 'user') {
    if (!projectId) {
      console.warn('Project ID not provided for user token refresh');
      // Возвращаем общий эндпоинт как запасной вариант
      return "/api/auth/refresh/";
    }
    return `/api/auth/user/${projectId}/refresh/`;
  }

  // Если тип не определен, используем старый общий эндпоинт
  return "/api/auth/refresh/";
}

/**
* Проверяет срок действия токена
* @returns {Object} - информация о сроке действия токена
*/
function checkTokenExpiration() {
  const token = getAccessToken();
  if (!token) return { isValid: false, expiresIn: 0 };

  const decoded = decodeToken(token);
  if (!decoded || !decoded.exp) return { isValid: false, expiresIn: 0 };

  const currentTime = Math.floor(Date.now() / 1000);
  const expiresIn = decoded.exp - currentTime;

  return {
    isValid: expiresIn > 0,
    expiresIn,
    expirationTime: new Date(decoded.exp * 1000),
    payload: decoded
  };
}

/**
* Получает ID проекта из текущего URL (для пользователей)
* @returns {string|null} - ID проекта или null
*/
function getProjectIdFromUrl() {
  // Извлекаем ID проекта из URL
  const projectMatch = window.location.pathname.match(/\/project\/([a-f0-9-]+)/i);
  return projectMatch ? projectMatch[1] : null;
}

/**
* Обработка принудительного выхода при ошибке обновления токенов
* @param {Error} error - ошибка
*/
function handleRefreshFailure(error) {
  console.error('Fatal token refresh error, logging out:', error);

  // Очищаем все токены
  clearTokens();

  // Перенаправляем на страницу логина с флагом ошибки
  window.location.href = '/login?error=session_expired';
}

// Экспортируем API сервиса
export default {
  getUserType,
  getUserTypeFromToken,
  getAccessToken,
  getRefreshToken,
  saveTokens,
  clearTokens,
  synchronizeTokens,
  isAuthenticated,
  decodeToken,
  checkTokenExpiration,
  getRefreshEndpoint,
  getProjectIdFromUrl,
  handleRefreshFailure
};