import React, { useState } from "react";
import {
  Card,
  Avatar,
  Typography,
  Form,
  Input,
  Button,
  Divider,
  notification,
} from "antd";
import {
  UserOutlined,
  MailOutlined,
  ArrowLeftOutlined,
} from "@ant-design/icons";
import { useNavigate } from "react-router-dom"; // Хук для навигации
import "../styles/ProfileSettings.css";

const { Title, Text } = Typography;

const ProfileSettings = () => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate(); // Инициализация хука для навигации

  // Данные пользователя
  const userData = {
    username: localStorage.getItem("Login"),
    email: localStorage.getItem("Email"),
  };

  const onFinish = (values) => {
    console.log("Submitted Values:", values);
    setLoading(true);

    // Имитация задержки при отправке данных
    setTimeout(() => {
      setLoading(false);
      notification.success({
        message: "Success",
        description: "Your settings have been updated successfully.",
      });
    }, 1000);
  };

  const handleBackClick = () => {
    navigate(-1); // Возвращаемся на предыдущую страницу
  };

  return (
    <div className="profile-settings-container">
      <Card className="profile-card">
        {/* Кнопка назад с уменьшенными размерами */}
        <Button
          icon={<ArrowLeftOutlined />}
          onClick={handleBackClick}
          style={{
            marginBottom: "20px",
            padding: "6px 12px", // Уменьшаем внутренние отступы
            fontSize: "14px", // Уменьшаем размер текста
            borderRadius: "4px", // Скругляем углы
          }}
        ></Button>

        <div className="profile-header">
          <Avatar
            size={100}
            icon={<UserOutlined />}
            style={{ cursor: "pointer", backgroundColor: "#243168" }}
          />
          <div className="profile-info">
            <Title level={3}>{userData.username}</Title>
            <Text type="secondary">{userData.email}</Text>
          </div>
        </div>

        <Divider />

        <Title level={4}>Update Your Settings</Title>
        <Form
          form={form}
          layout="vertical"
          onFinish={onFinish}
          initialValues={{
            username: userData.username,
            email: userData.email,
          }}
        >
          <Form.Item
            name="username"
            label="Username"
            rules={[{ required: true, message: "Please enter your username!" }]}
          >
            <Input
              prefix={<UserOutlined />}
              placeholder="Enter your username"
            />
          </Form.Item>

          <Form.Item
            name="email"
            label="Email"
            rules={[
              { required: true, message: "Please enter your email!" },
              { type: "email", message: "Please enter a valid email!" },
            ]}
          >
            <Input prefix={<MailOutlined />} placeholder="Enter your email" />
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>
              Save Changes
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
};

export default ProfileSettings;
