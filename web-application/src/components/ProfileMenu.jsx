import React from "react";
import { Avatar, Dropdown, Menu } from "antd";
import { useNavigate } from "react-router-dom";
import { UserOutlined, LogoutOutlined } from "@ant-design/icons";
import tokenRefreshService from "../services/tokenRefreshService";
import tokenService from "../services/tokenService";

const ProfileMenu = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    // Останавливаем сервис обновления токенов
    tokenRefreshService.stop();

    // Используем сервис для очистки всех токенов
    tokenService.clearTokens();

    // Перенаправляем на страницу логина
    navigate("/login");
  };

  const items = [
    {
      key: "profile",
      icon: <UserOutlined />,
      label: "Profile",
      onClick: () => navigate("/profile"),
    },
    {
      key: "logout",
      icon: <LogoutOutlined />,
      label: "Logout",
      onClick: handleLogout,
    },
  ];

  return (
    <Dropdown menu={{ items }} trigger={["click"]}>
      <Avatar
        size="large"
        icon={<UserOutlined />}
        style={{ cursor: "pointer", backgroundColor: "#243168" }}
      />
    </Dropdown>
  );
};

export default ProfileMenu;