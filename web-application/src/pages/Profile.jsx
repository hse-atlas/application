import React from "react";
import { Card, Divider, Button } from "antd";
import {
  MailOutlined,
  UserOutlined,
  ArrowLeftOutlined,
} from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import UserHeader from "../components/UserHeader";
import DetailItem from "../components/DetailItem";
import { useSelector } from "react-redux";
import "../styles/Profile.css";

const Profile = () => {
  const navigate = useNavigate();
  const user = useSelector((state) => state.user.data);

  const handleBackClick = () => {
    navigate(-1);
  };

  return (
    <div className="profile-page-container">
      <Card className="profile-card">
        <Button
          icon={<ArrowLeftOutlined />}
          onClick={handleBackClick}
          style={{ marginBottom: "20px" }}
        ></Button>
        {/* Используем данные из константы */}
        <UserHeader name={user.login} />
        <Divider />
        <div className="profile-details">
          <DetailItem
            icon={<MailOutlined className="detail-icon" />}
            label={`Email: ${user.email}`}
          />
          <DetailItem
            icon={<UserOutlined className="detail-icon" />}
            label={`Role: ${user.user_role}`}
          />
        </div>
        {/*
        <Divider />
        <Button
          className="edit-profile-button"
          type="primary"
          icon={<EditOutlined />}
          block
          onClick={handleSettingsClick}
        >
          Edit Profile
        </Button>
        */}
      </Card>
    </div>
  );
};

export default Profile;
