// tokenService.js

// Константы для ключей в localStorage
const ACCESS_TOKEN_KEY = "access_token";
const REFRESH_TOKEN_KEY = "refresh_token";
// Убрали упоминания USER_ACCESS/REFRESH, т.к. теперь тип токена определяется по его содержимому

/**
 * Получает access токен из localStorage
 * @returns {string|null} - access токен или null
 */
function getAccessToken() {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

/**
 * Получает refresh токен из localStorage
 * @returns {string|null} - refresh токен или null
 */
function getRefreshToken() {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

/**
 * Сохраняет токены в localStorage
 * @param {Object} tokens - объект с токенами {access_token, refresh_token}
 */
function saveTokens(tokens) {
  if (!tokens) return;
  const { access_token, refresh_token } = tokens;

  if (access_token) {
    localStorage.setItem(ACCESS_TOKEN_KEY, access_token);
    console.debug('[TokenService] Access token saved to localStorage.');
  } else {
    // Если access_token не пришел, удаляем старый (на всякий случай)
    localStorage.removeItem(ACCESS_TOKEN_KEY);
  }

  if (refresh_token) {
    localStorage.setItem(REFRESH_TOKEN_KEY, refresh_token);
    console.debug('[TokenService] Refresh token saved to localStorage.');
  } else {
    // Если refresh_token не пришел, удаляем старый
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  }
}

/**
 * Удаляет все токены из localStorage
 */
function clearTokens() {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  console.debug('[TokenService] Tokens cleared from localStorage.');
}

/**
 * Проверяет, есть ли access токен (признак авторизации)
 * @returns {boolean} - true, если есть access токен
 */
function isAuthenticated() {
  return !!getAccessToken();
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
    if (!base64Url) return null; // Проверка наличия payload
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    // Добавляем padding, если нужно
    const pad = base64.length % 4;
    const paddedBase64 = pad ? base64 + '===='.substring(pad) : base64;
    const jsonPayload = decodeURIComponent(
      atob(paddedBase64).split('').map(c => {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join('')
    );
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error('Error decoding token:', error, token); // Логируем сам токен при ошибке
    return null;
  }
}

/**
 * Проверяет срок действия access токена
 * @returns {Object} - информация о сроке действия { isValid: boolean, expiresIn: number, expirationTime: Date|null, payload: Object|null }
 */
function checkTokenExpiration() {
  const token = getAccessToken();
  if (!token) return { isValid: false, expiresIn: 0, expirationTime: null, payload: null };

  const decoded = decodeToken(token);
  // Проверяем наличие и тип exp
  if (!decoded || typeof decoded.exp !== 'number') {
    console.warn('[TokenService] Invalid token payload or missing exp field.');
    // Если токен не декодируется или нет exp, считаем его невалидным
    clearTokens(); // Очищаем невалидный токен
    return { isValid: false, expiresIn: 0, expirationTime: null, payload: null };
  }

  const currentTime = Math.floor(Date.now() / 1000);
  const expiresIn = decoded.exp - currentTime;

  return {
    isValid: expiresIn > 0,
    expiresIn, // секунд до истечения
    expirationTime: new Date(decoded.exp * 1000),
    payload: decoded // Возвращаем payload для возможного использования (например, usr_type)
  };
}

// Экспортируем API сервиса
export default {
  getAccessToken,
  getRefreshToken,
  saveTokens,
  clearTokens,
  // synchronizeTokens больше не нужен
  isAuthenticated,
  decodeToken,
  checkTokenExpiration
};