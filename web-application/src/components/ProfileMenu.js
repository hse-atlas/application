import React from "react";
import { Avatar, Dropdown, Menu } from "antd";
import { useNavigate } from "react-router-dom";
import { UserOutlined, LogoutOutlined } from "@ant-design/icons";
import tokenRefreshService from "../services/tokenRefreshService";

const ProfileMenu = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    // Останавливаем сервис обновления токенов
    tokenRefreshService.stop();

    // Очищаем localStorage
    localStorage.clear();

    // Очищаем cookies для токенов
    document.cookie = "admins_access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    document.cookie = "admins_refresh_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    document.cookie = "users_access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    document.cookie = "users_refresh_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";

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