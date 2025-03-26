import React, { useState } from "react";
import { Modal, Form, Input, Button, Space, message, Switch } from "antd";
import { addProject } from "../api";

const AddProject = ({ visible, onCancel, onAdd }) => {
  const [form] = Form.useForm();
  const [oauthEnabled, setOauthEnabled] = useState(false);
  const [oauthProviders, setOauthProviders] = useState({
    google: {
      enabled: false,
      client_id: "",
      client_secret: "",
      redirect_uri: "",
    },
    github: {
      enabled: false,
      client_id: "",
      client_secret: "",
      redirect_uri: "",
    },
    yandex: {
      enabled: false,
      client_id: "",
      client_secret: "",
      redirect_uri: "",
    },
    vk: { enabled: false, client_id: "", client_secret: "", redirect_uri: "" },
  });

  const handleAddProject = async (values) => {
    try {

      // Формируем данные для отправки
      const requestData = {
        name: values.name,
        description: values.description,
        url: values.URL || null,
        oauth_enabled: oauthEnabled,
        oauth_providers: {
          google: oauthProviders.google,
          github: oauthProviders.github,
          yandex: oauthProviders.yandex,
          vk: oauthProviders.vk,
          enabled: oauthEnabled,
        },
      };

      // Выводим данные в консоль для отладки
      console.log("Sending data to server:", requestData);

      // Отправляем запрос
      const response = await addProject(requestData);

      // Обработка успешного ответа
      onAdd(response.data);
      form.resetFields();
      message.success("Project added successfully!");
    } catch (error) {
      // Логирование ошибки
      console.error("Error creating project:", {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
      });
      message.error("Failed to create project.");
    }
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
            {
              required: true,
              message: "Please enter the project description!",
            },
          ]}
        >
          <Input.TextArea placeholder="Enter project description" />
        </Form.Item>

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

                {oauthProviders[provider].enabled && (
                  <>
                    <Form.Item label={`${provider.toUpperCase()} Client ID`}>
                      <Input
                        value={oauthProviders[provider].client_id}
                        onChange={(e) =>
                          setOauthProviders((prev) => ({
                            ...prev,
                            [provider]: {
                              ...prev[provider],
                              client_id: e.target.value,
                            },
                          }))
                        }
                      />
                    </Form.Item>

                    <Form.Item
                      label={`${provider.toUpperCase()} Client Secret`}
                    >
                      <Input
                        value={oauthProviders[provider].client_secret}
                        onChange={(e) =>
                          setOauthProviders((prev) => ({
                            ...prev,
                            [provider]: {
                              ...prev[provider],
                              client_secret: e.target.value,
                            },
                          }))
                        }
                      />
                    </Form.Item>

                    <Form.Item label={`${provider.toUpperCase()} Redirect URI`}>
                      <Input
                        value={oauthProviders[provider].redirect_uri}
                        onChange={(e) =>
                          setOauthProviders((prev) => ({
                            ...prev,
                            [provider]: {
                              ...prev[provider],
                              redirect_uri: e.target.value,
                            },
                          }))
                        }
                      />
                    </Form.Item>
                  </>
                )}
              </div>
            ))}
          </>
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
