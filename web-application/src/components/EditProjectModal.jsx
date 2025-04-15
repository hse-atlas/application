import React, { useEffect, useState } from "react";
import { Modal, Form, Input, Button, Space, message, Switch, Tag } from "antd";
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
  const [activeProviders, setActiveProviders] = useState([]);

  useEffect(() => {
    if (visible && initialValues) {
      form.setFieldsValue(initialValues);

      // Устанавливаем состояние OAuth из initialValues
      const oauthEnabled = initialValues.oauth_enabled || false;
      setOauthEnabled(oauthEnabled);

      const providersState = {
        google: { enabled: initialValues.oauth_providers?.google?.enabled || false },
        github: { enabled: initialValues.oauth_providers?.github?.enabled || false },
        yandex: { enabled: initialValues.oauth_providers?.yandex?.enabled || false },
        vk: { enabled: initialValues.oauth_providers?.vk?.enabled || false },
      };
      setOauthProviders(providersState);

      // Определяем активные провайдеры для отображения
      const active = [];
      if (providersState.google.enabled) active.push("Google");
      if (providersState.github.enabled) active.push("GitHub");
      if (providersState.yandex.enabled) active.push("Yandex");
      if (providersState.vk.enabled) active.push("VK");
      setActiveProviders(active);
    }
  }, [visible, initialValues, form]);

  const handleSave = async () => {
    try {
      if (!isValidUUID(id)) {
        message.error("Invalid project ID format");
        return;
      }

      const values = await form.validateFields();

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

  const updateActiveProviders = (providers) => {
    const active = [];
    if (providers.google.enabled) active.push("Google");
    if (providers.github.enabled) active.push("GitHub");
    if (providers.yandex.enabled) active.push("Yandex");
    if (providers.vk.enabled) active.push("VK");
    setActiveProviders(active);
  };

  const handleProviderToggle = (provider, checked) => {
    const newProviders = {
      ...oauthProviders,
      [provider]: { ...oauthProviders[provider], enabled: checked },
    };
    setOauthProviders(newProviders);
    updateActiveProviders(newProviders);
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

        <Form.Item label="OAuth Status">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Switch
              checked={oauthEnabled}
              onChange={(checked) => setOauthEnabled(checked)}
            />
            <span>{oauthEnabled ? 'Enabled' : 'Disabled'}</span>
            {oauthEnabled && activeProviders.length > 0 && (
              <div style={{ marginLeft: 'auto' }}>
                <span style={{ marginRight: 8 }}>Active providers:</span>
                {activeProviders.map(provider => (
                  <Tag color="blue" key={provider}>{provider}</Tag>
                ))}
              </div>
            )}
          </div>
        </Form.Item>

        {oauthEnabled && (
          <>
            <div style={{ margin: '16px 0', padding: '16px', border: '1px solid #d9d9d9', borderRadius: '4px' }}>
              <h4 style={{ marginBottom: '16px' }}>Configure OAuth Providers</h4>

              {["google", "github", "yandex", "vk"].map((provider) => (
                <div key={provider} style={{ marginBottom: "16px" }}>
                  <Form.Item label={`${provider.charAt(0).toUpperCase() + provider.slice(1)} OAuth`}>
                    <div style={{ display: 'flex', alignItems: 'center' }}>
                      <Switch
                        checked={oauthProviders[provider].enabled}
                        onChange={(checked) => handleProviderToggle(provider, checked)}
                        style={{ marginRight: 8 }}
                      />
                      <span>
                        {oauthProviders[provider].enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </div>
                  </Form.Item>
                </div>
              ))}
            </div>
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