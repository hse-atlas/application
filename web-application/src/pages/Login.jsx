import React, { useState } from "react";
import { Form, Input, Button, Typography, message, Divider, Space } from "antd";
import { useNavigate } from "react-router-dom";
import { GoogleOutlined, YandexOutlined } from "@ant-design/icons";
import { login } from "../api";
import tokenRefreshService from "../services/tokenRefreshService";
import "../styles/Login.css";

const { Title, Text } = Typography;

const Login = () => {
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const [form] = Form.useForm();

  const onFinish = async (values) => {
    setLoading(true);
    try {
      const response = await login({
        email: values.email,
        password: values.password,
      });

      const { access_token, refresh_token } = response.data;

      localStorage.setItem("access_token", access_token);
      localStorage.setItem("refresh_token", refresh_token);

      tokenRefreshService.start();

      message.success("Login successful!");

      setTimeout(() => {
        setLoading(false);
        navigate("/");
      }, 1000);
    } catch (error) {
      let errorMessage = "An error occurred during login";

      // Обрабатываем различные типы ошибок
      if (error.response) {
        // Ошибки валидации Pydantic (422 Unprocessable Entity)
        if (error.response.status === 422) {
          const errors = error.response.data.detail;
          if (Array.isArray(errors)) {
            // Обрабатываем все ошибки валидации
            errors.forEach((err) => {
              if (err.loc && err.loc.includes("email") && err.msg) {
                // Специальная обработка ошибки email
                message.error(err.msg);
                form.setFields([{
                  name: 'email',
                  errors: [err.msg],
                }]);
              } else if (err.loc && err.loc.includes("password") && err.msg) {
                // Обработка ошибки пароля
                message.error(err.msg);
                form.setFields([{
                  name: 'password',
                  errors: [err.msg],
                }]);
              } else if (err.msg) {
                // Общие ошибки валидации
                message.error(err.msg);
              }
            });
            setLoading(false);
            return;
          }
        }
        // Ошибки аутентификации (401 Unauthorized)
        else if (error.response.status === 401) {
          errorMessage = error.response.data.detail || "Invalid email or password";
          message.error(errorMessage);
        }
        // Другие ошибки сервера
        else {
          errorMessage = error.response.data.detail || error.response.statusText;
          message.error(errorMessage);
        }
      } else if (error.request) {
        // Ошибки сети (нет ответа от сервера)
        errorMessage = "No response from server. Please check your connection.";
        message.error(errorMessage);
      } else {
        // Другие ошибки
        errorMessage = error.message;
        message.error(errorMessage);
      }

      console.error("Login error:", errorMessage);
      setLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    window.location.href = "/api/auth/oauth/admin/google";
  };

  const handleYandexLogin = () => {
    window.location.href = "/api/auth/oauth/admin/yandex";
  };

  return (
    <div className="login-page-container">
      <div className="login-container">
        <Title level={2}>Welcome</Title>
        <div className="form-container">
          <Form
            form={form}
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
                {
                  type: 'email',
                  message: 'Please enter a valid email address!',
                }
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

          <Divider>or</Divider>

          <Space direction="vertical" style={{ width: '100%' }}>
            <Button
              icon={<GoogleOutlined />}
              onClick={handleGoogleLogin}
              block
            >
              Continue with Google
            </Button>
            <Button
              icon={<YandexOutlined />}
              onClick={handleYandexLogin}
              block
            >
              Continue with Yandex
            </Button>
          </Space>

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