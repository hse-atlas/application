// Файл: web-application/src/services/tokenService.js
// Полностью переписанная служба работы с токенами для использования только localStorage

const TOKEN_NAMES = {
  ADMIN_ACCESS: "admin_access_token",
  ADMIN_REFRESH: "admin_refresh_token",
  USER_ACCESS: "user_access_token",
  USER_REFRESH: "user_refresh_token"
};

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
 * Получает актуальный access токен из localStorage
 * @returns {string|null} - актуальный access токен или null
 */
function getAccessToken() {
  // Определяем тип пользователя из существующих токенов
  const adminToken = localStorage.getItem(TOKEN_NAMES.ADMIN_ACCESS);
  if (adminToken) {
    return adminToken;
  }

  const userToken = localStorage.getItem(TOKEN_NAMES.USER_ACCESS);
  if (userToken) {
    return userToken;
  }

  return null;
}

/**
 * Получает актуальный refresh токен из localStorage
 * @returns {string|null} - актуальный refresh токен или null
 */
function getRefreshToken() {
  // Определяем тип пользователя из текущего access токена
  const userType = getUserTypeFromToken();

  if (!userType) {
    // Если не можем определить тип из токена, проверяем наличие обоих типов рефреш токенов
    const adminRefreshToken = localStorage.getItem(TOKEN_NAMES.ADMIN_REFRESH);
    if (adminRefreshToken) {
      return adminRefreshToken;
    }

    const userRefreshToken = localStorage.getItem(TOKEN_NAMES.USER_REFRESH);
    if (userRefreshToken) {
      return userRefreshToken;
    }

    return null;
  }

  // Если тип известен, выбираем соответствующий токен
  if (userType === 'admin') {
    return localStorage.getItem(TOKEN_NAMES.ADMIN_REFRESH);
  } else {
    return localStorage.getItem(TOKEN_NAMES.USER_REFRESH);
  }
}

/**
 * Сохраняет токены в localStorage
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
    TOKEN_NAMES.ADMIN_ACCESS : TOKEN_NAMES.USER_ACCESS;

  const refreshStorageKey = userType === 'admin' ?
    TOKEN_NAMES.ADMIN_REFRESH : TOKEN_NAMES.USER_REFRESH;

  // Сохраняем в localStorage
  if (access_token) {
    localStorage.setItem(accessStorageKey, access_token);
  }

  if (refresh_token) {
    localStorage.setItem(refreshStorageKey, refresh_token);
  }

  // Удаляем токены другого типа для предотвращения конфликтов
  if (userType === 'admin') {
    localStorage.removeItem(TOKEN_NAMES.USER_ACCESS);
    localStorage.removeItem(TOKEN_NAMES.USER_REFRESH);
  } else {
    localStorage.removeItem(TOKEN_NAMES.ADMIN_ACCESS);
    localStorage.removeItem(TOKEN_NAMES.ADMIN_REFRESH);
  }
}

/**
 * Удаляет все токены из localStorage
 */
function clearTokens() {
  // Очищаем localStorage
  localStorage.removeItem(TOKEN_NAMES.ADMIN_ACCESS);
  localStorage.removeItem(TOKEN_NAMES.ADMIN_REFRESH);
  localStorage.removeItem(TOKEN_NAMES.USER_ACCESS);
  localStorage.removeItem(TOKEN_NAMES.USER_REFRESH);
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
  isAuthenticated,
  decodeToken,
  checkTokenExpiration,
  getRefreshEndpoint,
  getProjectIdFromUrl,
  handleRefreshFailure
};