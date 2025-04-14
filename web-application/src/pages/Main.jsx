import React, { useState, useEffect } from "react";
import { Table, Empty, Typography, Space, Button, Spin } from "antd";
import { PlusOutlined } from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import ProfileMenu from "../components/ProfileMenu";
import AddProject from "../components/AddProject";
import { getProjects, getMe } from "../api";
import { useDispatch, useSelector } from "react-redux";
import { setUserData } from "../store/userSlice";
import "../styles/Main.css";

const { Title, Text } = Typography;

const Main = () => {
  const [isModalVisible, setIsModalVisible] = useState(false);
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 10,
    showSizeChanger: true,
    pageSizeOptions: ['10', '20', '50'],
  });
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const user = useSelector((state) => state.user.data);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const [userResponse, projectsResponse] = await Promise.all([
          getMe(),
          getProjects()
        ]);

        dispatch(setUserData(userResponse.data));
        setProjects(Array.isArray(projectsResponse?.data) ? projectsResponse.data : []);
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

  const handleAddProject = async () => {
    try {
      const response = await getProjects();
      setProjects(response.data || []);
      setIsModalVisible(false);
    } catch (error) {
      console.error("Error refreshing projects:", error);
    }
  };

  const columns = [
    {
      title: "№",
      key: "index",
      render: (_, __, index) => (pagination.current - 1) * pagination.pageSize + index + 1,
      width: 60,
      align: 'center',
    },
    {
      title: "Project Name",
      dataIndex: "name",
      key: "name",
      sorter: (a, b) => a.name.localeCompare(b.name),
    },
    {
      title: "Description",
      dataIndex: "description",
      key: "description",
      ellipsis: true,
    },
    {
      title: "Users",
      dataIndex: "user_count",
      key: "user_count",
      sorter: (a, b) => a.user_count - b.user_count,
      width: 100,
      align: 'center',
    },
  ];

  const handleTableChange = (newPagination) => {
    setPagination({
      ...pagination,
      ...newPagination,
    });
  };

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
          <Table
            columns={columns}
            dataSource={projects}
            rowKey="id"
            pagination={pagination}
            onChange={handleTableChange}
            loading={loading}
            locale={{
              emptyText: loading ? <Spin tip="Loading..." /> : <Empty description="No Projects Found" />
            }}
            onRow={(record) => ({
              onClick: () => navigate(`/project/${record.id}`),
              style: { cursor: 'pointer' }
            })}
          />
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