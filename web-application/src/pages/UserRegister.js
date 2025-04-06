import React, { useState } from "react";
import { Form, Input, Button, Typography, message } from "antd";
import { useNavigate, useParams } from "react-router-dom";
import { registerUser, isValidUUID } from "../api"; // Импортируем isValidUUID
import "../styles/Register.css";

const { Title, Text } = Typography;

const Register = () => {
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const [errorMessage, setErrorMessage] = useState("");
  const { id } = useParams();

  const onFinish = async (values) => {
    setLoading(true);

    try {
      // Проверяем, что ID является валидным UUID
      if (!isValidUUID(id)) {
        throw new Error("Invalid project ID format");
      }

      await registerUser(id, {
        login: values.username,
        email: values.email,
        password: values.password,
      });

      localStorage.setItem("Login", values.username);
      message.success("Registration successful!");

      setTimeout(() => {
        navigate(`/userLogin/${id}`);
      }, 1000);
    } catch (error) {
      setErrorMessage(error.message);
      message.error(error.message);
    } finally {
      setLoading(false);
    }
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

          <div className="login-link">
            <Text>
              Already have an account?{" "}
              <a href={`${window.location.origin}/userLogin/${id}`}>Login</a>
            </Text>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;