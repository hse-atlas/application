import React, { useState, useEffect, use } from "react";
import { Table, Empty, Typography, Space, Button } from "antd";
import { PlusOutlined } from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import ProfileMenu from "../components/ProfileMenu";
import AddProject from "../components/AddProject";
import { getProjects, getMe } from "../api";
import { useDispatch, useSelector } from "react-redux";
import { setUserData, setUserError } from "../store/userSlice";
import "../styles/Main.css";

const { Title, Text } = Typography;

const Main = () => {
  const [isModalVisible, setIsModalVisible] = useState(false);
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const user = useSelector((state) => state.user.data);
  // Загрузка проектов при монтировании компонента
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        // Сначала получаем данные пользователя
        const userResponse = await getMe();
        console.log("Current user data:", userResponse.data);
        dispatch(setUserData(userResponse.data)); // Сохраняем в Redux

        // Затем получаем проекты
        const projectsResponse = await getProjects();
        setProjects(projectsResponse.data);
      } catch (error) {
        console.error("Error fetching data:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const handleAddProjectClick = () => setIsModalVisible(true);
  const handleModalCancel = () => setIsModalVisible(false);

  // Обновление списка после добавления проекта
  const handleAddProject = async () => {
    try {
      const accessToken = localStorage.getItem("access_token");
      const response = await getProjects(accessToken);
      setProjects(response.data);
      setIsModalVisible(false);
    } catch (error) {
      console.error("Error refreshing projects:", error);
    }
  };

  const columns = [
    {
      title: "№",
      key: "index",
      render: (_, __, index) => index + 1,
    },
    { title: "Project Name", dataIndex: "name", key: "name" },
    { title: "Description", dataIndex: "description", key: "description" },
    { title: "Users", dataIndex: "user_count", key: "user_count" },
  ];

  return (
    <div className="page-container">
      <div className="main-container">
        <div className="header">
          <Title level={2}>Projects</Title>
          <Space align="center" size="middle">
            <ProfileMenu />
            <Space direction="vertical">
              <Text type="secondary">
                {user?.user_role || "Role not specified"}
              </Text>
              <Text strong>{user?.email || "Email not available"}</Text>
            </Space>
          </Space>
        </div>
        <div style={{ textAlign: "right", marginBottom: 16 }}>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={handleAddProjectClick}
          >
            Add Project
          </Button>
        </div>

        <div className="projects-container">
          {loading ? (
            <div className="loading-container">Loading projects...</div>
          ) : projects.length > 0 ? (
            <Table
              dataSource={projects}
              columns={columns}
              rowKey="id"
              pagination={false}
              onRow={(record) => ({
                onClick: () => navigate(`/project/${record.id}`),
              })}
            />
          ) : (
            <div className="empty-container">
              <Empty description="No Projects Found" />
            </div>
          )}
        </div>

        <AddProject
          visible={isModalVisible}
          onCancel={handleModalCancel}
          onAdd={handleAddProject}
        />
      </div>
    </div>
  );
};

export default Main;
