import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Typography,
  Button,
  Table,
  Space,
  Empty,
  Spin,
  Alert,
  Popconfirm,
  message,
  Flex,
  Divider,
  Tag,
  Select,
} from "antd";
import {
  ArrowLeftOutlined,
  EditOutlined,
  DeleteFilled,
} from "@ant-design/icons";
import ProfileMenu from "../components/ProfileMenu";
import EditProjectModal from "../components/EditProjectModal";
import {
  getProjectDetails,
  deleteProject,
  deleteUser,
  changeUserRole,
  isValidUUID,
} from "../api"; // Импортируем isValidUUID
import { useSelector } from "react-redux";

const { Title, Text, Link } = Typography;
const { Option } = Select;

const ProjectDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [project, setProject] = useState(null);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isEditModalVisible, setIsEditModalVisible] = useState(false);
  const user = useSelector((state) => state.user.data);

  const inviteLink = `${window.location.origin}/userRegister/${id}`;

  useEffect(() => {
    const fetchProjectDetails = async () => {
      try {
        // Проверяем, что ID является валидным UUID
        if (!isValidUUID(id)) {
          setError("Invalid project ID format");
          setLoading(false);
          return;
        }

        const response = await getProjectDetails(id);
        setProject(response.data);
        setUsers(response.data.users);
      } catch (error) {
        setError(error.response?.data?.detail || "Ошибка при загрузке данных");
      } finally {
        setLoading(false);
      }
    };

    id && fetchProjectDetails();
  }, [id]);

  const handleEditClick = () => setIsEditModalVisible(true);

  const handleEditSave = (values) => {
    setProject((prev) => ({ ...prev, ...values }));
    setIsEditModalVisible(false);
  };

  const handleEditModalCancel = () => setIsEditModalVisible(false);

  const handleDelete = async () => {
    try {
      // Проверяем, что ID является валидным UUID
      if (!isValidUUID(id)) {
        message.error("Invalid project ID format");
        return;
      }

      await deleteProject(id);
      message.success("Project deleted successfully");
      navigate("/");
    } catch (error) {
      message.error(error.response?.data?.detail || "Failed to delete project");
    }
  };

  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(inviteLink);
      message.success("Link copied to clipboard!");
    } catch (err) {
      message.error("Failed to copy link");
    }
  };

  const handleDeleteUser = async (userId) => {
    try {
      await deleteUser(userId);
      setUsers((prev) => prev.filter((user) => user.id !== userId));
      message.success("User deleted successfully");
    } catch (error) {
      message.error(error.response?.data?.detail || "Failed to delete user");
    }
  };

  const handleRoleChange = async (userId, newRole) => {
    try {
      // Проверяем, что ID является валидным UUID
      if (!isValidUUID(id)) {
        message.error("Invalid project ID format");
        return;
      }

      // Преобразуем user_id в число
      const userIdNumber = parseInt(userId, 10);

      console.log("Sending data to server:", {
        project_id: id,
        user_id: userIdNumber,
        new_role: newRole,
      });

      // Отправляем запрос на сервер
      await changeUserRole(id, userIdNumber, newRole);

      // Обновляем состояние users
      setUsers((prev) =>
        prev.map((user) =>
          user.id === userId ? { ...user, role: newRole } : user
        )
      );

      message.success("User role updated successfully");
    } catch (error) {
      console.error("Error updating user role:", error);
      message.error(
        error.response?.data?.detail || "Failed to update user role"
      );
    }
  };

  const columns = [
    {
      title: "№",
      key: "index",
      render: (_, __, index) => index + 1,
      width: 50,
      align: "center",
    },
    {
      title: "Login",
      dataIndex: "login",
      key: "login",
      sorter: (a, b) => a.login.localeCompare(b.login),
    },
    {
      title: "Email",
      dataIndex: "email",
      key: "email",
      sorter: (a, b) => a.email.localeCompare(b.email),
    },
    {
      title: "Role",
      dataIndex: "role",
      key: "role",
      render: (role, record) => (
        <Select
          defaultValue={role}
          onChange={(value) => handleRoleChange(record.id, value)}
          style={{ width: 100 }}
        >
          <Option value="user">User</Option>
          <Option value="admin">Admin</Option>
        </Select>
      ),
      sorter: (a, b) => a.role.localeCompare(b.role),
      filters: [
        { text: "Admin", value: "admin" },
        { text: "User", value: "user" },
      ],
      onFilter: (value, record) => record.role === value,
    },
    {
      title: "Action",
      key: "action",
      render: (_, record) => (
        <Popconfirm
          title="Are you sure to delete this user?"
          onConfirm={() => handleDeleteUser(record.id)}
          okText="Yes"
          cancelText="No"
          placement="topRight"
        >
          <DeleteFilled style={{ color: "red", cursor: "pointer" }} />
        </Popconfirm>
      ),
      width: 100,
      align: "center",
    },
  ];

  if (loading) return <Spin size="large" fullscreen />;
  if (error) return <Alert message={error} type="error" showIcon fullscreen />;
  if (!project)
    return (
      <Alert message="Project not found" type="warning" showIcon fullscreen />
    );

  return (
    <div className="page-container">
      <div className="main-container">
        <div className="header">
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate(-1)} />
          <Title level={2}>{project.name}</Title>
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

        <Text type="secondary">{project.description}</Text>
        <Divider />

        <Flex justify="space-between" align="center">
          <Link onClick={handleCopyLink} style={{ cursor: "pointer" }}>
            Invite Users to this Project
          </Link>

          <Space>
            <Button
              type="primary"
              icon={<EditOutlined />}
              onClick={handleEditClick}
            >
              Edit project
            </Button>
            <Popconfirm
              title="Are you sure to delete this project?"
              onConfirm={handleDelete}
              okText="Yes"
              cancelText="No"
              placement="topRight"
            >
              <Button danger>Delete Project</Button>
            </Popconfirm>
          </Space>
        </Flex>

        <Title level={4} style={{ marginTop: 24 }}>
          Users
        </Title>
        <div className="projects-container">
          {users.length > 0 ? (
            <Table
              dataSource={users}
              columns={columns}
              rowKey="id"
              pagination={false}
              bordered
            />
          ) : (
            <Empty description="No users in project" />
          )}
        </div>
      </div>

      <EditProjectModal
        visible={isEditModalVisible}
        onCancel={handleEditModalCancel}
        onSave={handleEditSave}
        initialValues={{
          name: project.name,
          description: project.description,
          url: project.url,
        }}
      />
    </div>
  );
};

export default ProjectDetails;