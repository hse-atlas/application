import React, { useEffect, useState } from "react";
import { Modal, Form, Input, Button, Space, message, Switch } from "antd";
import { useNavigate, useParams } from "react-router-dom";
import { editeProject, isValidUUID } from "../api";

const EditProjectModal = ({ visible, onCancel, onSave, initialValues }) => {
  const [form] = Form.useForm();
  const navigate = useNavigate();
  const { id } = useParams();
  const [oauthEnabled, setOauthEnabled] = useState(false);
  const [oauthProviders, setOauthProviders] = useState({
    google: { enabled: false },
    github: { enabled: false },
    yandex: { enabled: false },
    vk: { enabled: false },
  });

  useEffect(() => {
    if (visible && initialValues) {
      form.setFieldsValue(initialValues);

      // Устанавливаем состояние OAuth из initialValues
      if (initialValues.oauth_enabled !== undefined) {
        setOauthEnabled(initialValues.oauth_enabled);
      }

      if (initialValues.oauth_providers) {
        setOauthProviders({
          google: { enabled: initialValues.oauth_providers.google?.enabled || false },
          github: { enabled: initialValues.oauth_providers.github?.enabled || false },
          yandex: { enabled: initialValues.oauth_providers.yandex?.enabled || false },
          vk: { enabled: initialValues.oauth_providers.vk?.enabled || false },
        });
      }
    }
  }, [visible, initialValues, form]);

  const handleSave = async () => {
    try {
      if (!isValidUUID(id)) {
        message.error("Invalid project ID format");
        return;
      }

      const values = await form.validateFields();

      // Формируем полные данные для отправки
      const requestData = {
        ...values,
        oauth_enabled: oauthEnabled,
        oauth_providers: {
          google: oauthProviders.google,
          github: oauthProviders.github,
          yandex: oauthProviders.yandex,
          vk: oauthProviders.vk,
        },
      };

      const response = await editeProject(id, requestData);

      if (response.status === 200) {
        message.success("Project updated successfully");
        onSave(response.data);
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
          rules={[{ required: true, message: "Please enter the project name!" }]}
        >
          <Input placeholder="Enter project name" />
        </Form.Item>

        <Form.Item
          name="description"
          label="Description"
          rules={[
            { required: true, message: "Please enter the project description!" },
          ]}
        >
          <Input.TextArea placeholder="Enter project description" />
        </Form.Item>

        <Form.Item label="Enable OAuth">
          <Switch
            checked={oauthEnabled}
            onChange={(checked) => setOauthEnabled(checked)}
          />
        </Form.Item>

        {oauthEnabled && (
          <>
            {["google", "github", "yandex", "vk"].map((provider) => (
              <div key={provider} style={{ marginBottom: "16px" }}>
                <Form.Item label={`Enable ${provider.toUpperCase()}`}>
                  <Switch
                    checked={oauthProviders[provider].enabled}
                    onChange={(checked) =>
                      setOauthProviders((prev) => ({
                        ...prev,
                        [provider]: { ...prev[provider], enabled: checked },
                      }))
                    }
                  />
                </Form.Item>
              </div>
            ))}
          </>
        )}
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