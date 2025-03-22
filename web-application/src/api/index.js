import axios from "axios";
const api = axios.create({
  baseURL: "/",
});

export const register = async (credentials) => {
  return api.post(
    "/api/v1/AuthService/api/v1/AuthService/register/",
    credentials
  );
};

export const login = async (credentials) => {
  return api.post("/api/v1/AuthService/api/v1/AuthService/login/", credentials);
};

export const getProjects = async (token) => {
  try {
    const response = await api.get("/projects/projects/owner", {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
    return response;
  } catch (error) {
    throw error;
  }
};

export const getMe = async (token) => {
  try {
    const response = await api.get(
      "/api/v1/AuthService/api/v1/AuthService/me",
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    return response;
  } catch (error) {
    throw error;
  }
};

export const addProject = async (token, data) => {
  try {
    const response = await api.post("/projects/projects/", data, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
    return response;
  } catch (error) {
    throw error;
  }
};

export const getProjectDetails = async (token, id) => {
  try {
    const response = await api.get(`/projects/projects/${id}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
    return response;
  } catch (error) {
    throw error;
  }
};

export const editeProject = async (token, id, data) => {
  try {
    const response = await api.put(`/projects/projects/owner/${id}`, data, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
    return response;
  } catch (error) {
    throw error;
  }
};

export const deleteProject = async (token, id) => {
  try {
    const response = await api.delete(`/projects/projects/owner/${id}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
    return response;
  } catch (error) {
    throw error;
  }
};

export const deleteUser = async (token, id) => {
  try {
    const response = await api.delete(`/users/users/${id}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
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

export const changeUserRole = async (token, project_id, user_id, new_role) => {
  try {
    const response = await api.put(
      `/projects/${project_id}/users/${user_id}/role`,
      { new_role }, // Отправляем данные в правильном формате
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    return response;
  } catch (error) {
    throw error;
  }
};
