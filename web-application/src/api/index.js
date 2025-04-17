// ./api/index.js
import axios from "axios";
import tokenService from "../services/tokenService"; // Используем обновленный сервис

// Создаем экземпляр axios с базовым URL
const api = axios.create({
  baseURL: window.location.origin, // Или ваш API_URL из .env
  // withCredentials: false // Убираем, т.к. больше не работаем с cookie
  // timeout: 10000 // Можно добавить таймаут (10 секунд)
});

// --- Логика очереди запросов и обновления токена ---
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token); // Передаем новый токен для повторного запроса
    }
  });
  failedQueue = [];
};

// Функция для обновления токенов
const refreshAuthToken = async () => {
  // Предотвращаем повторный запуск, если уже обновляем
  if (isRefreshing) {
    // Возвращаем промис, который разрешится/отклонится при завершении текущего обновления
    return new Promise((resolve, reject) => {
      failedQueue.push({ resolve, reject });
    });
  }

  isRefreshing = true;

  try {
    console.log('%c[API] 🔄 Starting token refresh...', 'background: #e6f7ff; color: #1890ff; padding: 2px 4px; border-radius: 2px;');
    const refreshToken = tokenService.getRefreshToken();
    if (!refreshToken) {
      console.warn('[API] No refresh token available for refresh.');
      throw new Error('No refresh token available'); // Выбрасываем ошибку, чтобы обработать в catch
    }

    // Используем тот же api instance, т.к. интерсептор запроса добавит Authorization,
    // а интерсептор ответа не должен вызвать рекурсию для /refresh эндпоинта
    // (но можно создать и отдельный, если есть проблемы)
    const response = await api.post("/api/auth/refresh/", {
      // Передаем токен в теле, как ожидает бэкенд
      refresh_token: refreshToken
    }, {
      _isRetryRequest: true // Добавляем флаг, чтобы интерсептор ответа не обрабатывал ошибку этого запроса как 401
    });

    const { access_token, refresh_token } = response.data;
    tokenService.saveTokens({ access_token, refresh_token }); // Сохраняем новые токены

    console.log('%c[API] ✅ Tokens refreshed successfully!', 'background: #f6ffed; color: #52c41a; padding: 2px 4px; border-radius: 2px;');
    processQueue(null, access_token); // Обрабатываем очередь с новым токеном
    return access_token; // Возвращаем новый токен

  } catch (error) {
    console.log('%c[API] ❌ Token refresh failed.', 'background: #fff2f0; color: #f5222d; padding: 2px 4px; border-radius: 2px;', error.response?.data || error.message);
    processQueue(error, null); // Обрабатываем очередь с ошибкой
    tokenService.clearTokens(); // Очищаем токены при неудаче

    // Перенаправляем на логин ТОЛЬКО если это не ошибка сети/отмены
    // и сервер явно сказал, что токен невалиден (например, 401 на /refresh)
    if (error.response && (error.response.status === 401 || error.response.status === 400)) {
      console.log('[API] Redirecting to login due to refresh failure.');
      // Используем window.location для перезагрузки страницы и редиректа
      if (window.location.pathname !== '/login') { // Предотвращаем редирект, если уже на логине
        window.location.href = '/login';
      }
    }
    // Перебрасываем ошибку дальше, чтобы оригинальный запрос тоже завершился неудачно
    throw error;
  } finally {
    isRefreshing = false; // Сбрасываем флаг после завершения
  }
};

// Интерсептор ответа
api.interceptors.response.use(
  (response) => {
    // Успешный ответ - ничего не делаем с токенами здесь
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Проверяем, была ли ошибка 401 и не является ли это повторным запросом или запросом на обновление
    if (error.response && error.response.status === 401 && !originalRequest._isRetryRequest) {
      console.warn('[API] Received 401 Unauthorized. Attempting token refresh.');
      originalRequest._isRetryRequest = true; // Помечаем, чтобы избежать рекурсии

      try {
        const newToken = await refreshAuthToken(); // Запускаем обновление (оно само обработает очередь)
        // Если обновление успешно, новый токен уже будет в localStorage
        // Интерсептор запроса сам подставит его при повторе
        console.log('[API] Retrying original request with new token.');
        return api(originalRequest); // Повторяем оригинальный запрос
      } catch (refreshError) {
        // Если обновление не удалось, refreshAuthToken уже сделал редирект/очистку
        // Просто перебрасываем ошибку, чтобы Promise оригинального запроса отклонился
        return Promise.reject(refreshError);
      }
    }

    // Для других ошибок просто пробрасываем их дальше
    return Promise.reject(error);
  }
);

// Интерсептор запроса
api.interceptors.request.use(
  (config) => {
    // Добавляем актуальный access токен из localStorage
    const token = tokenService.getAccessToken();
    if (token && !config.headers.Authorization) { // Добавляем, только если еще не установлен (например, при повторном запросе)
      config.headers.Authorization = `Bearer ${token}`;
      console.debug('[API] Added Authorization header to request:', config.url);
    }
    // Убираем withCredentials, если он там был
    // config.withCredentials = false;
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Функция для проактивной проверки и обновления (вызывается из tokenRefreshService)
export const checkAndRefreshTokenIfNeeded = async () => {
  try {
    const tokenInfo = tokenService.checkTokenExpiration();

    if (!tokenInfo.isValid) {
      console.log('%c[API] Token is not valid or expired.', 'color: #f5222d;');
      // Пытаемся обновить, если есть refresh токен
      if (tokenService.getRefreshToken()) {
        console.log('[API] Attempting refresh due to invalid access token.');
        await refreshAuthToken(); // Запускаем обновление
      } else {
        console.log('[API] No refresh token available, cannot refresh.');
        tokenService.clearTokens(); // Очищаем на всякий случай
        // Редирект, если не на логине
        if (window.location.pathname !== '/login') {
          window.location.href = '/login';
        }
      }
      return; // Выходим, т.к. токен невалиден
    }

    // Порог для обновления (например, 5 минут = 300 секунд)
    const REFRESH_THRESHOLD_SECONDS = 300;

    if (tokenInfo.expiresIn < REFRESH_THRESHOLD_SECONDS) {
      console.log('%c[API] ⏰ Token expires soon, attempting proactive refresh...', 'background: #fffbe6; color: #faad14; padding: 2px 4px; border-radius: 2px;', {
        expires_in_seconds: tokenInfo.expiresIn,
        token_exp: tokenInfo.expirationTime.toLocaleTimeString()
      });
      await refreshAuthToken(); // Запускаем обновление
    } else {
      // console.log('%c[API] ✓ Token is still valid.', 'color: #52c41a;', {
      //   expires_in_minutes: Math.floor(tokenInfo.expiresIn / 60),
      //   token_exp: tokenInfo.expirationTime.toLocaleTimeString()
      // });
    }
  } catch (error) {
    // Ошибки обновления обрабатываются внутри refreshAuthToken
    console.error('[API] Error during proactive token check/refresh:', error.message);
  }
};

// Проверка на валидный UUID
export const isValidUUID = (str) => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(str);
};

// Экспорт API функций

export const register = async (credentials) => {
  return api.post(
    "/api/auth/admin/register/",
    credentials
  );
};

export const login = async (credentials) => {
  return api.post("/api/auth/admin/login/", credentials);
};

export const getProjects = async () => {
  try {
    // Проверяем и при необходимости обновляем токен перед запросом
    await checkAndRefreshTokenIfNeeded();
    const response = await api.get("/api/projects/");
    return response;
  } catch (error) {
    throw error;
  }
};

export const getMe = async () => {
  try {
    // Проверяем и при необходимости обновляем токен перед запросом
    await checkAndRefreshTokenIfNeeded();
    const response = await api.get(
      "/api/auth/admin/me"
    );
    return response;
  } catch (error) {
    throw error;
  }
};

export const addProject = async (data) => {
  try {
    await checkAndRefreshTokenIfNeeded();
    const response = await api.post("/api/projects/", data);
    return response;
  } catch (error) {
    throw error;
  }
};

export const getProjectDetails = async (id) => {
  try {
    // Проверяем, что ID является валидным UUID
    if (!isValidUUID(id)) {
      throw new Error("Invalid project ID format");
    }

    await checkAndRefreshTokenIfNeeded();
    const response = await api.get(`/api/projects/${id}`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const editeProject = async (id, data) => {
  try {
    // Проверяем, что ID является валидным UUID
    if (!isValidUUID(id)) {
      throw new Error("Invalid project ID format");
    }

    await checkAndRefreshTokenIfNeeded();
    const response = await api.put(`/api/projects/${id}`, data);
    return response;
  } catch (error) {
    throw error;
  }
};

export const deleteProject = async (id) => {
  try {
    // Проверяем, что ID является валидным UUID
    if (!isValidUUID(id)) {
      throw new Error("Invalid project ID format");
    }

    await checkAndRefreshTokenIfNeeded();
    const response = await api.delete(`/api/projects/${id}`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const deleteUser = async (id) => {
  try {
    await checkAndRefreshTokenIfNeeded();
    const response = await api.delete(`/api/users/${id}`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const blockUser = async (user_id) => {
  try {
    await checkAndRefreshTokenIfNeeded();
    const response = await api.patch(`/api/users/${user_id}/block`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const unblockUser = async (user_id) => {
  try {
    await checkAndRefreshTokenIfNeeded();
    const response = await api.patch(`/api/users/${user_id}/unblock`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const registerUser = async (project_id, data) => {
  try {
    // Проверяем, что ID является валидным UUID
    if (!isValidUUID(project_id)) {
      throw new Error("Invalid project ID format");
    }

    const response = await api.post(
      `/api/auth/user/register/${project_id}`,
      data
    );
    return response.data;
  } catch (error) {
    throw error;
  }
};

export const loginUser = async (project_id, data) => {
  try {
    // Проверяем, что ID является валидным UUID
    if (!isValidUUID(project_id)) {
      throw new Error("Invalid project ID format");
    }

    const response = await api.post(
      `/api/auth/user/login/${project_id}`,
      data
    );
    return response.data;
  } catch (error) {
    const errorMessage = error.response?.data?.detail || "Login failed";
    throw new Error(errorMessage);
  }
};

export const getProjectRedirectUrl = async (project_id) => {
  try {
    // Проверяем, что ID является валидным UUID
    if (!isValidUUID(project_id)) {
      throw new Error("Invalid project ID format");
    }
    const response = await api.get(`/api/projects/${project_id}/url`);
    return response.data;
  } catch (error) {
    const errorMessage =
      error.response?.data?.detail || "Failed to get redirect URL";
    throw new Error(errorMessage);
  }
};

export const changeUserRole = async (project_id, user_id, new_role) => {
  try {
    // Проверяем, что project_id является валидным UUID
    if (!isValidUUID(project_id)) {
      throw new Error("Invalid project ID format");
    }

    await checkAndRefreshTokenIfNeeded();
    const response = await api.put(
      `/api/projects/${project_id}/users/${user_id}/role`,
      { new_role }
    );
    return response;
  } catch (error) {
    throw error;
  }
};

export const getProjectUsers = async (project_id) => {
  try {
    // Проверяем, что ID является валидным UUID
    if (!isValidUUID(project_id)) {
      throw new Error("Invalid project ID format");
    }

    await checkAndRefreshTokenIfNeeded();
    const response = await api.get(`/api/projects/${project_id}/users`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const getProjectUser = async (project_id, user_id) => {
  try {
    // Проверяем, что ID является валидным UUID
    if (!isValidUUID(project_id)) {
      throw new Error("Invalid project ID format");
    }

    await checkAndRefreshTokenIfNeeded();
    const response = await api.get(`/api/projects/${project_id}/users/${user_id}`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const deleteProjectUser = async (project_id, user_id) => {
  try {
    // Проверяем, что ID является валидным UUID
    if (!isValidUUID(project_id)) {
      throw new Error("Invalid project ID format");
    }

    await checkAndRefreshTokenIfNeeded();
    const response = await api.delete(`/api/projects/${project_id}/users/${user_id}`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const updateProjectOAuth = async (project_id, oauth_settings) => {
  try {
    // Проверяем, что ID является валидным UUID
    if (!isValidUUID(project_id)) {
      throw new Error("Invalid project ID format");
    }

    await checkAndRefreshTokenIfNeeded();
    const response = await api.put(`/api/projects/${project_id}/oauth`, oauth_settings);
    return response;
  } catch (error) {
    throw error;
  }
};

/**
 * Получает публичную конфигурацию OAuth для проекта
 * @param {string} projectId - ID проекта
 * @returns {Promise<Object>} - Объект с { oauth_enabled: boolean, enabled_providers: string[] }
 */
export const getProjectOAuthConfig = async (projectId) => {
  try {
    const response = await api.get(`/api/projects/${projectId}/oauth-config`);
    return response.data;
  } catch (error) {
    console.error(`Error fetching OAuth config for project ${projectId}:`, error);
    // Перебрасываем ошибку, чтобы ее можно было поймать в компоненте
    throw error;
  }
};