import axios from "axios";

// Создаем экземпляр axios с базовым URL
const api = axios.create({
  baseURL: "/",
  withCredentials: true // Важно для работы с cookie
});

// Добавляем интерсептор для проверки наличия обновленных токенов в Cookie после каждого ответа
api.interceptors.response.use(
  (response) => {
    // Проверяем заголовки Cookie в ответе
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
  (error) => {
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
    const response = await api.get("/projects/projects/owner");
    return response;
  } catch (error) {
    throw error;
  }
};

export const getMe = async () => {
  try {
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
    const response = await api.post("/projects/projects/", data);
    return response;
  } catch (error) {
    throw error;
  }
};

export const getProjectDetails = async (id) => {
  try {
    const response = await api.get(`/projects/projects/${id}`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const editeProject = async (id, data) => {
  try {
    const response = await api.put(`/projects/projects/owner/${id}`, data);
    return response;
  } catch (error) {
    throw error;
  }
};

export const deleteProject = async (id) => {
  try {
    const response = await api.delete(`/projects/projects/owner/${id}`);
    return response;
  } catch (error) {
    throw error;
  }
};

export const deleteUser = async (id) => {
  try {
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
    const response = await api.put(
      `/projects/${project_id}/users/${user_id}/role`,
      { new_role }
    );
    return response;
  } catch (error) {
    throw error;
  }
};