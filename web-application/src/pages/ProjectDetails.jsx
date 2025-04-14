import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useSelector } from "react-redux";
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
  Switch,
} from "antd";
import {
  ArrowLeftOutlined,
  EditOutlined,
  DeleteFilled,
  LockOutlined,
  UnlockOutlined,
} from "@ant-design/icons";
import ProfileMenu from "../components/ProfileMenu";
import EditProjectModal from "../components/EditProjectModal";
import {
  getProjectDetails,
  deleteProject,
  changeUserRole,
  isValidUUID,
  blockUser,
  unblockUser,
} from "../api";

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

  useEffect(() => {
    const fetchProjectDetails = async () => {
      try {
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

  const handleToggleBlock = async (userId, currentStatus) => {
    try {
      const userIdNumber = parseInt(userId, 10);

      if (currentStatus === 'active') {
        await blockUser(id, userIdNumber);
        setUsers(prev => prev.map(user =>
          user.id === userId ? { ...user, status: 'blocked' } : user
        ));
        message.success("User blocked successfully");
      } else {
        await unblockUser(id, userIdNumber);
        setUsers(prev => prev.map(user =>
          user.id === userId ? { ...user, status: 'active' } : user
        ));
        message.success("User unblocked successfully");
      }
    } catch (error) {
      message.error(error.response?.data?.detail || "Failed to update user status");
    }
  };

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

  const handleCopyUUID = async () => {
    try {
      await navigator.clipboard.writeText(id);
      message.success("UUID copied to clipboard!");
    } catch (err) {
      message.error("Failed to copy UUID");
    }
  };

  /*
  const handleDeleteUser = async (userId) => {
    try {
      await deleteUser(userId);
      setUsers((prev) => prev.filter((user) => user.id !== userId));
      message.success("User deleted successfully");
    } catch (error) {
      message.error(error.response?.data?.detail || "Failed to delete user");
    }
  };
  */

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
      render: (text, record) => (
        <span style={{
          color: record.status === 'blocked' ? '#999' : 'inherit',
          fontStyle: record.status === 'blocked' ? 'italic' : 'normal'
        }}>
          {text}
        </span>
      )
    },
    {
      title: "Email",
      dataIndex: "email",
      key: "email",
      sorter: (a, b) => a.email.localeCompare(b.email),
      render: (text, record) => (
        <span style={{
          color: record.status === 'blocked' ? '#999' : 'inherit',
          fontStyle: record.status === 'blocked' ? 'italic' : 'normal'
        }}>
          {text}
        </span>
      )
    },
    {
      title: "Role",
      dataIndex: "role",
      key: "role",
      render: (role, record) => (
        <Select
          value={role}
          onChange={(value) => handleRoleChange(record.id, value)}
          style={{ width: 100 }}
          disabled={record.status === 'blocked'}
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
      title: "Status",
      dataIndex: "status",
      key: "status",
      render: (status) => (
        <Tag color={status === 'active' ? 'green' : 'red'}>
          {status === 'active' ? 'Active' : 'Blocked'}
        </Tag>
      ),
      filters: [
        { text: "Active", value: "active" },
        { text: "Blocked", value: "blocked" },
      ],
      onFilter: (value, record) => record.status === value,
    },
    {
      title: "Action",
      key: "action",
      render: (_, record) => (
        <Popconfirm
          title={`Are you sure to ${record.status === 'active' ? 'block' : 'unblock'} this user?`}
          onConfirm={() => handleToggleBlock(record.id, record.status)}
          okText="Yes"
          cancelText="No"
          placement="topRight"
        >
          {record.status === 'active' ? (
            <LockOutlined style={{ color: '#ff4d4f', cursor: 'pointer' }} />
          ) : (
            <UnlockOutlined style={{ color: '#52c41a', cursor: 'pointer' }} />
          )}
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
          <Link onClick={handleCopyUUID} style={{ cursor: "pointer" }}>
            Copy UUID for integration forms
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