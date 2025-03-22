import React, { useState } from "react";
import { Form, Input, Button, Typography, message } from "antd"; // Импортируем message
import { useNavigate } from "react-router-dom";
import axios from "axios"; // Импортируем axios
import { login } from "../api";
import "../styles/Login.css";

const { Title, Text } = Typography;

const Login = (onLogin) => {
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const onFinish = async (values) => {
    setLoading(true);
    try {
      // Отправка запроса к бэкенду для получения токенов
      const response = await login({
        email: values.email,
        password: values.password,
      });

      const { access_token, refresh_token } = response.data;

      // Сохранение токенов в localStorage
      localStorage.setItem("access_token", access_token);
      localStorage.setItem("refresh_token", refresh_token);

      // Временное перенаправление на главную страницу
      setTimeout(() => {
        setLoading(false);
        navigate("/"); // Перенаправление на главную страницу
      }, 1000);
    } catch (error) {
      // Обработка ошибок
      const errorMessage = error.response?.data?.detail || "An error occurred";
      console.error("Login error:", errorMessage);

      // Отображаем ошибку с помощью message из antd
      message.error(errorMessage);

      setLoading(false);
    }
  };

  return (
    <div className="login-page-container">
      <div className="login-container">
        <Title level={2}>Welcome</Title>
        <div className="form-container">
          <Form
            name="login"
            layout="vertical"
            onFinish={onFinish}
            autoComplete="off"
            requiredMark={false}
          >
            <Form.Item
              name="email"
              label="Email"
              rules={[
                {
                  required: true,
                  message: "Please enter your email!",
                },
              ]}
            >
              <Input placeholder="Enter your email" />
            </Form.Item>

            <Form.Item
              name="password"
              label="Password"
              rules={[
                { required: true, message: "Please enter your password!" },
              ]}
            >
              <Input.Password placeholder="Enter your password" />
            </Form.Item>

            <Form.Item>
              <Button type="primary" htmlType="submit" block loading={loading}>
                Login
              </Button>
            </Form.Item>
          </Form>

          <div className="register-link">
            <Text>
              Don't have an account? <a href="/register">Register</a>
            </Text>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
