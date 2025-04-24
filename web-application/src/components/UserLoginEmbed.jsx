// UserLoginEmbed.jsx
import React, { useState, useEffect } from "react";
import { Form, Input, Button, message, Divider, Space, Spin } from "antd";
import { useParams } from "react-router-dom";
import { loginUser, isValidUUID, getProjectOAuthConfig } from "../api";
import tokenService from "../services/tokenService";
import { GoogleOutlined, WeiboOutlined } from '@ant-design/icons';

const OAUTH_BUTTONS = {
    google: ({ projectId }) => (
        <Button
            icon={<GoogleOutlined />}
            onClick={() => handleOAuthLogin('google', projectId)}
            block
        >
            Continue with Google
        </Button>
    ),
    yandex: ({ projectId }) => (
        <Button
            icon={<WeiboOutlined />}
            onClick={() => handleOAuthLogin('yandex', projectId)}
            block
        >
            Continue with Yandex
        </Button>
    ),
};

const handleOAuthLogin = (provider, projectId) => {
    if (!projectId) {
        console.error("Project ID is missing for OAuth login");
        message.error("Cannot initiate OAuth login: project ID missing.");
        return;
    }
    const oauthUrl = `https://atlas.appweb.space/api/auth/oauth/user/${provider}/${projectId}`;
    window.top.location.href = oauthUrl;
};

const UserLoginEmbed = () => {
    const [loading, setLoading] = useState(false);
    const [oauthConfig, setOAuthConfig] = useState({
        loading: true,
        enabled: false,
        providers: []
    });
    const { id: projectId } = useParams();

    useEffect(() => {
        const fetchOAuthConfig = async () => {
            if (!projectId || !isValidUUID(projectId)) {
                console.error("Invalid or missing project ID in URL");
                setOAuthConfig({ loading: false, enabled: false, providers: [] });
                return;
            }
            try {
                const config = await getProjectOAuthConfig(projectId);
                setOAuthConfig({
                    loading: false,
                    enabled: config.oauth_enabled,
                    providers: config.enabled_providers || []
                });
            } catch (error) {
                console.error("Error fetching OAuth config:", error);
                message.error("Could not load login options.");
                setOAuthConfig({ loading: false, enabled: false, providers: [] });
            }
        };

        fetchOAuthConfig();
    }, [projectId]);

    const onFinish = async (values) => {
        setLoading(true);
        try {
            if (!isValidUUID(projectId)) {
                throw new Error("Invalid project ID format");
            }
            const response = await loginUser(projectId, {
                email: values.email,
                password: values.password,
            });

            tokenService.saveTokens({
                access_token: response.access_token,
                refresh_token: response.refresh_token
            });

            // Отправляем сообщение родительскому окну с токенами
            window.parent.postMessage({
                type: "ATLAS_AUTH_SUCCESS",
                tokens: {
                    access_token: response.access_token,
                    refresh_token: response.refresh_token
                }
            }, "*"); // Укажите конкретный origin вместо "*" в production!

        } catch (error) {
            console.error("Login error:", error);
            message.error(error.response?.data?.detail || error.message || "Login failed");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ padding: 20, maxWidth: 400, margin: "0 auto" }}>
            <Form
                name="login"
                layout="vertical"
                onFinish={onFinish}
                autoComplete="off"
            >
                <Form.Item
                    name="email"
                    label="Email"
                    rules={[{ type: "email", required: true, message: 'Please input a valid Email!' }]}
                >
                    <Input />
                </Form.Item>

                <Form.Item
                    name="password"
                    label="Password"
                    rules={[{ required: true, message: 'Please input your Password!' }]}
                >
                    <Input.Password />
                </Form.Item>

                <Form.Item>
                    <Button type="primary" htmlType="submit" block loading={loading}>
                        Login
                    </Button>
                </Form.Item>
            </Form>

            {oauthConfig.loading ? (
                <div style={{ textAlign: 'center', marginTop: 20 }}><Spin /></div>
            ) : oauthConfig.enabled && oauthConfig.providers.length > 0 ? (
                <>
                    <Divider>or</Divider>
                    <Space direction="vertical" style={{ width: '100%' }}>
                        {oauthConfig.providers.map(providerName => {
                            const ButtonComponent = OAUTH_BUTTONS[providerName];
                            return ButtonComponent ? <ButtonComponent key={providerName} projectId={projectId} /> : null;
                        })}
                    </Space>
                </>
            ) : null}
        </div>
    );
};

export default UserLoginEmbed;