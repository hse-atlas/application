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
  const [form] = Form.useForm();

  const onFinish = async (values) => {
    setLoading(true);
    try {
      const response = await register({
        login: values.username,
        email: values.email,
        password: values.password,
      });

      message.success(response.data.message || "Registration successful!");
      console.log("Registration successful:", response.data);

      // Очищаем форму после успешной регистрации
      form.resetFields();

      // Перенаправление на страницу входа с небольшой задержкой
      setTimeout(() => {
        navigate("/login");
      }, 1500);
    } catch (error) {
      let errorMessage = "Registration failed. Please try again.";

      // Обрабатываем различные типы ошибок
      if (error.response) {
        // Ошибки от сервера
        if (error.response.status === 409) {
          // Конфликты (уже существующий email или логин)
          errorMessage = error.response.data.detail;
        } else if (error.response.status === 400) {
          // Ошибки валидации (например, пароль не соответствует требованиям)
          errorMessage = error.response.data.detail;
        } else {
          // Другие ошибки сервера
          errorMessage = error.response.data.detail || error.response.statusText;
        }
      } else if (error.request) {
        // Ошибки сети (нет ответа от сервера)
        errorMessage = "Network error. Please check your connection.";
      }

      console.error("Registration error:", errorMessage);
      message.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    window.location.href = "/api/auth/oauth/admin/google";
  };

  return (
    <div className="register-page-container">
      <div className="register-container">
        <Title level={2}>Create an Account</Title>
        <div className="form-container">
          <Form
            form={form}
            name="register"
            layout="vertical"
            onFinish={onFinish}
            autoComplete="off"
          >
            <Form.Item
              name="username"
              label="Username"
              rules={[
                {
                  required: true,
                  message: "Please enter your username!"
                },
                {
                  min: 3,
                  message: "Username must be at least 3 characters long",
                },
                {
                  max: 20,
                  message: "Username must be at most 20 characters long",
                },
              ]}
            >
              <Input placeholder="Enter your username" />
            </Form.Item>

            <Form.Item
              name="email"
              label="Email"
              rules={[
                {
                  required: true,
                  message: "Please enter your email!"
                },
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
                {
                  required: true,
                  message: "Please enter your password!"
                },
                {
                  min: 8,
                  message: "Password must be at least 8 characters long",
                },
              ]}
              help="Password must be at least 8 characters long"
            >
              <Input.Password placeholder="Enter your password" />
            </Form.Item>

            <Form.Item
              name="confirm"
              label="Confirm Password"
              dependencies={["password"]}
              hasFeedback
              rules={[
                {
                  required: true,
                  message: "Please confirm your password!"
                },
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
              <Button
                type="primary"
                htmlType="submit"
                block
                loading={loading}
                disabled={loading}
              >
                Register
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