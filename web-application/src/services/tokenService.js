// tokenService.js - единый сервис для управления токенами

const TOKEN_NAMES = {
  ACCESS: {
    cookie: "admins_access_token",
    storage: "access_token"
  },
  REFRESH: {
    cookie: "admins_refresh_token",
    storage: "refresh_token"
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
 * Синхронизирует токены между cookie и localStorage
 * Приоритет имеют токены из cookie
 */
function synchronizeTokens() {
  console.debug('Synchronizing tokens between cookies and localStorage');

  // Проверка и синхронизация для access_token
  const accessTokenCookie = getTokenFromCookie(TOKEN_NAMES.ACCESS.cookie);
  const userAccessTokenCookie = getTokenFromCookie(TOKEN_NAMES.USER_ACCESS.cookie);

  // Приоритет: admin token, затем user token
  if (accessTokenCookie) {
    localStorage.setItem(TOKEN_NAMES.ACCESS.storage, accessTokenCookie);
  } else if (userAccessTokenCookie) {
    localStorage.setItem(TOKEN_NAMES.ACCESS.storage, userAccessTokenCookie);
  }

  // То же самое для refresh токенов
  const refreshTokenCookie = getTokenFromCookie(TOKEN_NAMES.REFRESH.cookie);
  const userRefreshTokenCookie = getTokenFromCookie(TOKEN_NAMES.USER_REFRESH.cookie);

  if (refreshTokenCookie) {
    localStorage.setItem(TOKEN_NAMES.REFRESH.storage, refreshTokenCookie);
  } else if (userRefreshTokenCookie) {
    localStorage.setItem(TOKEN_NAMES.REFRESH.storage, userRefreshTokenCookie);
  }
}

/**
 * Получает актуальный access токен с предварительной синхронизацией
 * @returns {string|null} - актуальный access токен или null
 */
function getAccessToken() {
  synchronizeTokens();
  return localStorage.getItem(TOKEN_NAMES.ACCESS.storage);
}

/**
 * Получает актуальный refresh токен с предварительной синхронизацией
 * @returns {string|null} - актуальный refresh токен или null
 */
function getRefreshToken() {
  synchronizeTokens();
  return localStorage.getItem(TOKEN_NAMES.REFRESH.storage);
}

/**
 * Сохраняет токены в localStorage и в cookies
 * @param {Object} tokens - объект с токенами {access_token, refresh_token}
 * @param {string} userType - тип пользователя ('admin' или 'user')
 */
function saveTokens(tokens, userType = 'admin') {
  if (!tokens) return;

  const { access_token, refresh_token } = tokens;
  const isAdmin = userType === 'admin';

  // Сохраняем в localStorage
  if (access_token) {
    localStorage.setItem(TOKEN_NAMES.ACCESS.storage, access_token);
  }

  if (refresh_token) {
    localStorage.setItem(TOKEN_NAMES.REFRESH.storage, refresh_token);
  }

  // Сохраняем в cookies с помощью JS, если их нет
  const accessCookieName = isAdmin ? TOKEN_NAMES.ACCESS.cookie : TOKEN_NAMES.USER_ACCESS.cookie;
  const refreshCookieName = isAdmin ? TOKEN_NAMES.REFRESH.cookie : TOKEN_NAMES.USER_REFRESH.cookie;

  // Проверяем, что токены в cookie либо отсутствуют, либо отличаются от наших
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
  localStorage.removeItem(TOKEN_NAMES.ACCESS.storage);
  localStorage.removeItem(TOKEN_NAMES.REFRESH.storage);

  // Очищаем cookies
  const pastDate = new Date(0).toUTCString();
  document.cookie = `${TOKEN_NAMES.ACCESS.cookie}=; expires=${pastDate}; path=/;`;
  document.cookie = `${TOKEN_NAMES.REFRESH.cookie}=; expires=${pastDate}; path=/;`;
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

// Экспортируем API сервиса
export default {
  getAccessToken,
  getRefreshToken,
  saveTokens,
  clearTokens,
  synchronizeTokens,
  isAuthenticated,
  decodeToken,
  checkTokenExpiration
};