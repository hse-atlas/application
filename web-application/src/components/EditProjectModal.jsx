import React, { useEffect } from "react";
import { Modal, Form, Input, Button, Space, message } from "antd";
import { useNavigate, useParams } from "react-router-dom";
import { editeProject, isValidUUID } from "../api"; // Импортируем isValidUUID

const EditProjectModal = ({ visible, onCancel, onSave, initialValues }) => {
  const [form] = Form.useForm();
  const navigate = useNavigate();
  const { id } = useParams();

  useEffect(() => {
    if (visible) {
      form.setFieldsValue(initialValues);
    }
  }, [visible, initialValues, form]);

  const handleSave = async () => {
    try {
      // Проверяем, что ID является валидным UUID
      if (!isValidUUID(id)) {
        message.error("Invalid project ID format");
        return;
      }

      const values = await form.validateFields();

      // Вызываем API-метод
      const response = await editeProject(id, values);

      if (response.status === 200) {
        message.success("Project updated successfully");
        onSave(response.data); // Передаем обновленные данные
        onCancel();
      }
    } catch (error) {
      console.error("Update error:", error);
      message.error(error.response?.data?.detail || "Failed to update project");
    }
  };

  return (
    <Modal
      title="Edit Project"
      open={visible}
      onCancel={onCancel}
      footer={null}
    >
      <Form form={form} layout="vertical">
        <Form.Item
          name="name"
          label="Project Name"
          rules={[
            { required: true, message: "Please enter the project name!" },
          ]}
        >
          <Input placeholder="Enter project name" />
        </Form.Item>

        <Form.Item
          name="description"
          label="Description"
          rules={[
            {
              required: true,
              message: "Please enter the project description!",
            },
          ]}
        >
          <Input.TextArea placeholder="Enter project description" />
        </Form.Item>

        {/*
        <Form.Item
          name="url"
          label="Project URL"
          rules={[
            {
              type: "url",
              message: "Please enter a valid URL!",
            },
          ]}
        >
          <Input placeholder="Enter project URL" />
        </Form.Item>
        */}



      </Form>

      <div style={{ textAlign: "right", marginTop: "16px" }}>
        <Space>
          <Button onClick={onCancel}>Cancel</Button>
          <Button type="primary" onClick={handleSave}>
            Save Changes
          </Button>
        </Space>
      </div>
    </Modal>
  );
};

export default EditProjectModal;