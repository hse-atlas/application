import React from "react";
import { Avatar, Typography } from "antd";
import { UserOutlined } from "@ant-design/icons";

const { Title, Text } = Typography;

const UserHeader = ({ name, username, avatarSize = 100 }) => {
  return (
    <div className="user-header">
      <Avatar size={avatarSize} icon={<UserOutlined />} />
      <Title level={2} className="user-name">
        {name}
      </Title>
      <Text type="secondary">{username}</Text>
    </div>
  );
};

export default UserHeader;
