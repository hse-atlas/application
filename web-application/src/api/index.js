import axios from "axios";

// Создаем экземпляр axios с базовым URL
const api = axios.create({
  baseURL: "/",
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
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    // Создаем новый экземпляр axios без интерсепторов, чтобы избежать рекурсии
    const refreshApi = axios.create({
      baseURL: "/",
      withCredentials: true
    });

    // Запрос на обновление токенов
    const response = await refreshApi.post("/api/v1/AuthService/api/v1/AuthService/refresh/", {
      refresh_token: refreshToken
    });

    // Сохраняем новые токены
    const { access_token, refresh_token } = response.data;
    localStorage.setItem('access_token', access_token);
    localStorage.setItem('refresh_token', refresh_token);

    console.log('%c[Token] ✅ Tokens refreshed successfully!', 'background: #f6ffed; color: #52c41a; padding: 2px 4px; border-radius: 2px;', {
      access_token_starts_with: access_token.substring(0, 15) + '...',
      refresh_token_starts_with: refresh_token.substring(0, 15) + '...'
    });

    return access_token;
  } catch (error) {
    console.log('%c[Token] ❌ Token refresh failed', 'background: #fff2f0; color: #f5222d; padding: 2px 4px; border-radius: 2px;', error);
    // При ошибке обновления, вынуждаем пользователя перелогиниться
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');

    // Редирект на страницу логина
    window.location.href = '/login';
    throw error;
  }
};

// Добавляем интерсептор для обработки ошибок и автоматического обновления токенов
api.interceptors.response.use(
  (response) => {
    // Проверяем заголовки Cookie в ответе для синхронизации с localStorage
    const cookies = document.cookie.split(';').reduce((cookies, cookie) => {
      const [name, value] = cookie.trim().split('=');
      cookies[name] = value;
      return cookies;
    }, {});

    // Обновляем токены в localStorage, если они есть в cookie
    if (cookies.admins_access_token) {
      localStorage.setItem('access_token', cookies.admins_access_token);
      console.log('Access token updated from cookie');
    }

    if (cookies.admins_refresh_token) {
      localStorage.setItem('refresh_token', cookies.admins_refresh_token);
      console.log('Refresh token updated from cookie');
    }

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
    const token = localStorage.getItem("access_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Проверка срока действия access_token и проактивное обновление
export const checkAndRefreshTokenIfNeeded = async () => {
  try {
    // Получение токена
    const token = localStorage.getItem('access_token');
    if (!token) return;

    // Декодирование JWT (без проверки подписи)
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64).split('').map(c => {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join('')
    );

    const { exp } = JSON.parse(jsonPayload);
    if (!exp) return;

    // Получаем текущее время в секундах
    const currentTime = Math.floor(Date.now() / 1000);

    // Если токен истекает в течение следующих 5 минут, обновляем его
    if (exp - currentTime < 300) { // 300 секунд = 5 минут
      console.log('%c[Token] ⏰ Token will expire soon, refreshing...', 'background: #fffbe6; color: #faad14; padding: 2px 4px; border-radius: 2px;', {
        expires_in_seconds: exp - currentTime,
        token_exp: new Date(exp * 1000).toLocaleTimeString()
      });
      await refreshTokens();
    } else {
      console.log('%c[Token] ✓ Token valid', 'color: #52c41a;', {
        expires_in_minutes: Math.floor((exp - currentTime) / 60),
        token_exp: new Date(exp * 1000).toLocaleTimeString()
      });
    }
  } catch (error) {
    console.error('Error checking token expiration:', error);
  }
};

// Экспорт API функций

export const register = async (credentials) => {
  return api.post(
    "/api/v1/AuthService/api/v1/AuthService/register/",
    credentials
  );
};

export const login = async (credentials) => {
  return api.post("/api/v1/AuthService/api/v1/AuthService/login/", credentials);
};

export const getProjects = async () => {
  try {
    // Проверяем и при необходимости обновляем токен перед запросом
    await checkAndRefreshTokenIfNeeded();
    const response = await api.get("/projects/projects/owner");
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
      "/api/v1/AuthService/api/v1/AuthService/me"
    );
    return response;
  } catch (error) {
    throw error;
  }
};

export const addProject = async (data) => {
  try {
    await checkAndRefreshTokenIfNeeded();
    const response = await api.post("/projects/projects/", data);
    return response;
  } catch (error) {
    throw error;
  }
};

export const getProjectDetails = async (id) => {
  try {
    await checkAndRefreshTokenIfNeeded();
    const response = await api.get(`/projects/projects/${id}`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const editeProject = async (id, data) => {
  try {
    await checkAndRefreshTokenIfNeeded();
    const response = await api.put(`/projects/projects/owner/${id}`, data);
    return response;
  } catch (error) {
    throw error;
  }
};

export const deleteProject = async (id) => {
  try {
    await checkAndRefreshTokenIfNeeded();
    const response = await api.delete(`/projects/projects/owner/${id}`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const deleteUser = async (id) => {
  try {
    await checkAndRefreshTokenIfNeeded();
    const response = await api.delete(`/users/users/${id}`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const registerUser = async (project_id, data) => {
  try {
    const response = await api.post(
      `/api/v1/AuthService/api/v1/AuthService/user_register/${project_id}`,
      data
    );
    return response;
  } catch (error) {
    throw error;
  }
};

export const loginUser = async (project_id, data) => {
  try {
    const response = await api.post(
      `/api/v1/AuthService/api/v1/AuthService/user_login/${project_id}`,
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
    const response = await api.get(`/projects/projects/getURL/${project_id}`);
    return response.data;
  } catch (error) {
    const errorMessage =
      error.response?.data?.detail || "Failed to get redirect URL";
    throw new Error(errorMessage);
  }
};

export const changeUserRole = async (project_id, user_id, new_role) => {
  try {
    await checkAndRefreshTokenIfNeeded();
    const response = await api.put(
      `/projects/${project_id}/users/${user_id}/role`,
      { new_role }
    );
    return response;
  } catch (error) {
    throw error;
  }
};