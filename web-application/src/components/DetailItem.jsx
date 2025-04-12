import React from "react";
import { Typography } from "antd";

const { Text } = Typography;

const DetailItem = ({ icon, label }) => {
  return (
    <div className="detail-item">
      {icon}
      <Text>{label}</Text>
    </div>
  );
};

export default DetailItem;
