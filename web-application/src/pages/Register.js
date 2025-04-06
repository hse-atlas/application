import React, { useState } from "react";
import { Form, Input, Button, Typography, message, Divider } from "antd";
import { GoogleOutlined } from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import { register } from "../api";
import "../styles/Register.css";

const { Title, Text } = Typography;

const Register = () => {
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const [errorMessage, setErrorMessage] = useState(""); // создаем состояние для ошибки

  const onFinish = async (values) => {
    setLoading(true);
    try {
      // Отправляем данные на сервер
      const response = await register({
        login: values.username,
        email: values.email,
        password: values.password,
      });

      console.log("Registration successful:", response.data);
      // Временное перенаправление на страницу входа после успешной регистрации
      setTimeout(() => {
        setLoading(false);
        navigate("/login"); // Перенаправление на страницу входа
      }, 1000);
    } catch (error) {
      // Проверяем наличие сообщения об ошибке
      const errorMessage = error.response?.data?.detail || "An error occurred";
      console.error("Registration error:", errorMessage);

      // Устанавливаем ошибку в состояние для отображения на фронте
      setErrorMessage(errorMessage); // Например, у вас может быть состояние для ошибки

      // Отображаем сообщение об ошибке
      message.error(errorMessage); // Показываем всплывающее сообщение с ошибкой

      setLoading(false);
    }
  };

  // Добавляем функцию для входа через Google
  const handleGoogleLogin = () => {
    window.location.href = "/api/auth/oauth/admin/google";
  };

  return (
    <div className="register-page-container">
      <div className="register-container">
        <Title level={2}>Create an Account</Title>
        <div className="form-container">
          <Form
            name="register"
            layout="vertical"
            onFinish={onFinish}
            autoComplete="off"
          >
            <Form.Item
              name="username"
              label="Username"
              rules={[
                { required: true, message: "Please enter your username!" },
              ]}
            >
              <Input placeholder="Enter your username" />
            </Form.Item>

            <Form.Item
              name="email"
              label="Email"
              rules={[
                { required: true, message: "Please enter your email!" },
                {
                  type: "email",
                  message: "Please enter a valid email address!",
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

            <Form.Item
              name="confirm"
              label="Confirm Password"
              dependencies={["password"]}
              hasFeedback
              rules={[
                { required: true, message: "Please confirm your password!" },
                ({ getFieldValue }) => ({
                  validator(_, value) {
                    if (!value || getFieldValue("password") === value) {
                      return Promise.resolve();
                    }
                    return Promise.reject("The passwords do not match!");
                  },
                }),
              ]}
            >
              <Input.Password placeholder="Confirm your password" />
            </Form.Item>

            <Form.Item>
              <Button type="primary" htmlType="submit" block loading={loading}>
                Register
              </Button>
            </Form.Item>
          </Form>

          {/* Добавляем разделитель и кнопку для регистрации через Google */}
          <Divider>or</Divider>

          <Button
            icon={<GoogleOutlined />}
            onClick={handleGoogleLogin}
            block
            style={{ marginBottom: '16px' }}
          >
            Sign up with Google
          </Button>

          <div className="login-link">
            <Text>
              Already have an account? <a href="/login">Login</a>
            </Text>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;