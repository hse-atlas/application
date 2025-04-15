import React, { useEffect, useState } from "react";
import { Modal, Form, Input, Button, Space, message, Switch, Tag } from "antd";
import { useNavigate, useParams } from "react-router-dom";
import { editeProject, isValidUUID } from "../api";

const EditProjectModal = ({ visible, onCancel, onSave, initialValues }) => {
  const [form] = Form.useForm();
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
      form.setFieldsValue({
        name: initialValues.name,
        description: initialValues.description,
        url: initialValues.url
      });

      // Инициализация OAuth состояния
      const oauthEnabled = initialValues.oauth_enabled || false;
      setOauthEnabled(oauthEnabled);

      // Инициализация провайдеров
      const providersFromDB = initialValues.oauth_providers || {};
      const providersState = {
        google: { enabled: providersFromDB.google?.enabled || false },
        github: { enabled: providersFromDB.github?.enabled || false },
        yandex: { enabled: providersFromDB.yandex?.enabled || false },
        vk: { enabled: providersFromDB.vk?.enabled || false },
      };
      setOauthProviders(providersState);
      updateActiveProviders(providersState);
    }
  }, [visible, initialValues, form]);

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

  const handleSave = async () => {
    try {
      const values = await form.validateFields();

      const requestData = {
        ...values,
        oauth_enabled: oauthEnabled,
        oauth_providers: oauthEnabled ? oauthProviders : null,
      };

      onSave(requestData);
      onCancel();
    } catch (error) {
      console.error("Validation error:", error);
      message.error("Please fill all required fields correctly");
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
          <div style={{ margin: '16px 0', padding: '16px', border: '1px solid #d9d9d9', borderRadius: '4px' }}>
            <h4 style={{ marginBottom: '16px' }}>Configure OAuth Providers</h4>

            {["google", "github", "yandex", "vk"].map((provider) => (
              <div key={provider} style={{ marginBottom: "16px" }}>
                <Form.Item label={`${provider.charAt(0).toUpperCase() + provider.slice(1)} OAuth`}>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Switch
                      checked={oauthProviders[provider]?.enabled || false}
                      onChange={(checked) => handleProviderToggle(provider, checked)}
                      style={{ marginRight: 8 }}
                    />
                    <span>
                      {oauthProviders[provider]?.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                </Form.Item>
              </div>
            ))}
          </div>
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