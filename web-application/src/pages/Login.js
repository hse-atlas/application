import React, { useState } from "react";
import { Form, Input, Button, Typography, message, Divider, Space } from "antd";
import { useNavigate } from "react-router-dom";
import { GoogleOutlined } from "@ant-design/icons";
import { login } from "../api";
import tokenRefreshService from "../services/tokenRefreshService";
import "../styles/Login.css";

const { Title, Text } = Typography;

const Login = () => {
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

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

      // Проверяем наличие ответа от сервера
      if (error.response) {
        // Если бэкенд вернул детали ошибки в поле detail
        if (error.response.data && error.response.data.detail) {
          errorMessage = error.response.data.detail;
        }
        // Если бэкенд вернул другую структуру ошибки
        else if (error.response.data) {
          errorMessage = JSON.stringify(error.response.data);
        }
      } else if (error.request) {
        errorMessage = "No response from server";
      } else {
        errorMessage = error.message;
      }

      console.error("Login error:", errorMessage);
      message.error(errorMessage);
      setLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    window.location.href = "/api/auth/oauth/admin/google";
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

          <Divider>or</Divider>

          <Button
            icon={<GoogleOutlined />}
            onClick={handleGoogleLogin}
            block
            style={{ marginBottom: '16px' }}
          >
            Continue with Google
          </Button>

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