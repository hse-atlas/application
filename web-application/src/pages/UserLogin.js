import React, { useState } from "react";
import { Form, Input, Button, Typography, message } from "antd";
import { useNavigate, useParams } from "react-router-dom";
import { loginUser, getProjectRedirectUrl, isValidUUID } from "../api"; // Импортируем isValidUUID
import "../styles/Login.css";

const { Title, Text } = Typography;

const UserLogin = () => {
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { id } = useParams();

  const onFinish = async (values) => {
    setLoading(true);

    try {
      // Проверяем, что ID является валидным UUID
      if (!isValidUUID(id)) {
        throw new Error("Invalid project ID format");
      }

      // Выполняем вход пользователя
      const { access_token, refresh_token } = await loginUser(id, {
        email: values.email,
        password: values.password,
      });

      // Сохраняем токены в localStorage
      localStorage.setItem("access_token", access_token);
      localStorage.setItem("refresh_token", refresh_token);

      // Получаем URL для перенаправления
      const redirectUrl = await getProjectRedirectUrl(id);
      const validRedirectUrl = new URL(redirectUrl).href;

      message.success("Login successful!");
      window.location.href = validRedirectUrl;
    } catch (error) {
      message.error(error.message);
    } finally {
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
              rules={[{ required: true, message: "Please enter your email!" }]}
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
              Don't have an account?{" "}
              <a href={`${window.location.origin}/userRegister/${id}`}>
                Register
              </a>
            </Text>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserLogin;