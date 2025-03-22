import React from "react";
import { Avatar, Dropdown, Menu } from "antd";
import { useNavigate } from "react-router-dom";
import { UserOutlined, LogoutOutlined } from "@ant-design/icons";

const ProfileMenu = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.clear(); // Полностью очищаем localStorage
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
