import React, { useState } from "react";
import { Modal, Form, Input, Button, Space, message, Switch, Tag } from "antd";
import { addProject } from "../api";

const AddProject = ({ visible, onCancel, onAdd }) => {
  const [form] = Form.useForm();
  const [oauthEnabled, setOauthEnabled] = useState(false);
  const [oauthProviders, setOauthProviders] = useState({
    google: { enabled: false },
    github: { enabled: false },
    yandex: { enabled: false },
    vk: { enabled: false },
  });
  const [activeProviders, setActiveProviders] = useState([]);

  const handleAddProject = async (values) => {
    if (oauthEnabled && activeProviders.length === 0) {
      message.error("At least one OAuth provider must be enabled.");
      return;
    }

    try {
      const requestData = {
        name: values.name,
        description: values.description,
        url: values.url || null,
        oauth_enabled: oauthEnabled,
        oauth_providers: oauthEnabled ? oauthProviders : null,
      };

      console.log("Sending data to server:", requestData);
      const response = await addProject(requestData);

      onAdd(response.data);
      form.resetFields();
      setOauthEnabled(false);
      setOauthProviders({
        google: { enabled: false },
        github: { enabled: false },
        yandex: { enabled: false },
        vk: { enabled: false },
      });
      setActiveProviders([]);
      message.success("Project added successfully!");
    } catch (error) {
      console.error("Error creating project:", {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
      });
      message.error("Failed to create project.");
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
      title="Add New Project"
      visible={visible}
      onCancel={onCancel}
      footer={null}
    >
      <Form form={form} layout="vertical" onFinish={handleAddProject}>
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
            { required: true, message: "Please enter the project description!" },
          ]}
        >
          <Input.TextArea placeholder="Enter project description" />
        </Form.Item>

        <Form.Item
          name="url"
          label="Project URL"
          rules={[
            {
              required: true,
              type: "url",
              message: "Please enter a valid URL!",
            },
          ]}
        >
          <Input placeholder="Enter project URL" />
        </Form.Item>

        <Form.Item label="OAuth Status">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Switch
              checked={oauthEnabled}
              onChange={(checked) => setOauthEnabled(checked)}
            />
            <span>{oauthEnabled ? 'Enabled' : 'Disabled'}</span>
            {oauthEnabled && activeProviders.length > 0 ? (
              <div style={{ marginLeft: 'auto' }}>
                <span style={{ marginRight: 8 }}>Active providers:</span>
                {activeProviders.map(provider => (
                  <Tag color="blue" key={provider}>{provider}</Tag>
                ))}
              </div>
            ) : null}
          </div></Form.Item>
        
        
        {oauthEnabled && (
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
        )}

        <div style={{ textAlign: "right", marginTop: "16px" }}>
          <Space>
            <Button onClick={onCancel}>Cancel</Button>
            <Button type="primary" htmlType="submit">
              Add
            </Button>
          </Space>
        </div>
      </Form>
    </Modal>
  );
};

export default AddProject;