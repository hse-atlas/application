import axios from "axios";
import tokenService from "../services/tokenService";

// Создаем экземпляр axios с базовым URL
const api = axios.create({
  baseURL: window.location.origin,
  withCredentials: true // Важно для работы с cookie
});

// Флаг для отслеживания, выполняется ли сейчас обновление токена
let isRefreshing = false;
// Очередь запросов, ожидающих обновления токена
let failedQueue = [];

// Функция обработки очереди запросов после обновления токена
const processQueue = (error, token = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });

  failedQueue = [];
};

// Функция для обновления токенов с использованием refresh_token
const refreshTokens = async () => {
  try {
    console.log('%c[Token] 🔄 Starting token refresh...', 'background: #e6f7ff; color: #1890ff; padding: 2px 4px; border-radius: 2px;');

    // Получаем актуальный refresh токен через сервис
    const refreshToken = tokenService.getRefreshToken();
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    // Получаем тип пользователя из refresh токена
    const refreshTokenDecoded = tokenService.decodeToken(refreshToken);
    const userType = refreshTokenDecoded?.user_type;

    if (!userType) {
      throw new Error('Invalid refresh token: missing user_type');
    }

    // Определяем эндпоинт обновления токенов на основе типа пользователя из токена
    let refreshEndpoint;
    if (userType === 'admin') {
      refreshEndpoint = "/api/auth/admin/refresh/";
    } else if (userType === 'user') {
      const projectId = tokenService.getProjectIdFromUrl();
      if (!projectId) {
        refreshEndpoint = "/api/auth/refresh/"; // Общий эндпоинт как запасной вариант
      } else {
        refreshEndpoint = `/api/auth/user/${projectId}/refresh/`;
      }
    } else {
      refreshEndpoint = "/api/auth/refresh/"; // Общий эндпоинт для неизвестных типов
    }

    console.log(`Using refresh endpoint: ${refreshEndpoint} for user_type: ${userType}`);

    // Создаем новый экземпляр axios без интерсепторов, чтобы избежать рекурсии
    const refreshApi = axios.create({
      baseURL: "/",
      withCredentials: true
    });

    // Запрос на обновление токенов
    const response = await refreshApi.post(refreshEndpoint, {
      refresh_token: refreshToken
    });

    // Сохраняем новые токены через сервис
    const { access_token, refresh_token } = response.data;
    tokenService.saveTokens({ access_token, refresh_token });

    console.log('%c[Token] ✅ Tokens refreshed successfully!', 'background: #f6ffed; color: #52c41a; padding: 2px 4px; border-radius: 2px;', {
      access_token_starts_with: access_token.substring(0, 15) + '...',
      refresh_token_starts_with: refresh_token.substring(0, 15) + '...'
    });

    return access_token;
  } catch (error) {
    console.log('%c[Token] ❌ Token refresh failed', 'background: #fff2f0; color: #f5222d; padding: 2px 4px; border-radius: 2px;', error);

    // Используем обработчик ошибок из tokenService
    tokenService.handleRefreshFailure(error);
    throw error;
  }
};

// Добавляем интерсептор для обработки ответов и синхронизации токенов
api.interceptors.response.use(
  (response) => {
    // Синхронизируем токены после каждого ответа
    tokenService.synchronizeTokens();
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Проверяем, была ли ошибка из-за истекшего токена (401)
    if (error.response && error.response.status === 401 && !originalRequest._retry) {
      // Помечаем запрос как retry, чтобы избежать бесконечной рекурсии
      originalRequest._retry = true;

      // Если уже выполняется обновление токена, добавляем запрос в очередь
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then(token => {
            originalRequest.headers['Authorization'] = `Bearer ${token}`;
            return api(originalRequest);
          })
          .catch(err => {
            return Promise.reject(err);
          });
      }

      isRefreshing = true;

      try {
        // Получаем новый токен
        const newToken = await refreshTokens();

        // Обрабатываем очередь запросов
        processQueue(null, newToken);

        // Повторяем оригинальный запрос с новым токеном
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        // Обрабатываем очередь с ошибкой
        processQueue(refreshError, null);
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

// Добавляем интерсептор для авторизации запросов
api.interceptors.request.use(
  (config) => {
    // Получаем актуальный токен через сервис
    const token = tokenService.getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

export const checkAndRefreshTokenIfNeeded = async () => {
  try {
    // Проверяем срок действия токена через сервис
    const tokenInfo = tokenService.checkTokenExpiration();

    if (!tokenInfo.isValid) {
      console.log('%c[Token] ❌ Token not valid', 'color: #f5222d;');
      // Если токен недействителен, запускаем логаут
      tokenService.handleRefreshFailure(new Error('Token expired'));
      return;
    }

    // Если токен истекает в течение следующих 5 минут, обновляем его
    if (tokenInfo.expiresIn < 300) {
      console.log('%c[Token] ⏰ Token will expire soon, refreshing...', 'background: #fffbe6; color: #faad14; padding: 2px 4px; border-radius: 2px;', {
        expires_in_seconds: tokenInfo.expiresIn,
        token_exp: tokenInfo.expirationTime.toLocaleTimeString()
      });
      await refreshTokens();
    } else {
      console.log('%c[Token] ✓ Token valid', 'color: #52c41a;', {
        expires_in_minutes: Math.floor(tokenInfo.expiresIn / 60),
        token_exp: tokenInfo.expirationTime.toLocaleTimeString()
      });
    }
  } catch (error) {
    console.error('Error checking token expiration:', error);
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