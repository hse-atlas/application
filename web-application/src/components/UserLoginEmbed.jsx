// UserLoginEmbed.jsx
import React, { useState, useEffect } from "react";
import { Form, Input, Button, message, Divider, Space, Spin } from "antd"; // Добавили Divider, Space, Spin
import { useParams, useNavigate } from "react-router-dom"; // Добавили useNavigate (если нужно перенаправление)
import { loginUser, isValidUUID, getProjectOAuthConfig } from "../api"; // Добавили getProjectOAuthConfig
import tokenService from "../services/tokenService";
// Импортируем иконки
import { GoogleOutlined, WeiboOutlined /* добавьте другие иконки по мере необходимости */ } from '@ant-design/icons';

// --- Добавлено: Маппинг имен провайдеров на компоненты кнопок ---
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
            // Замените WeiboOutlined на иконку Яндекса, если найдете или создадите
            icon={<WeiboOutlined />}
            onClick={() => handleOAuthLogin('yandex', projectId)}
            block
        >
            Continue with Yandex
        </Button>
    ),
    // github: ({ projectId }) => ( ... ),
    // vk: ({ projectId }) => ( ... ),
};

// --- Добавлено: Обработчик клика по кнопке OAuth ---
const handleOAuthLogin = (provider, projectId) => {
    if (!projectId) {
        console.error("Project ID is missing for OAuth login");
        message.error("Cannot initiate OAuth login: project ID missing.");
        return;
    }
    // Формируем URL для пользовательского OAuth
    window.parent.location.href = `/api/auth/oauth/user/${provider}/${projectId}`;
    // Используем window.parent.location.href, чтобы редирект произошел в родительском окне,
    // а не внутри iframe (если форма встроена через iframe)
    // Если форма не в iframe, можно использовать window.location.href
};


const UserLoginEmbed = () => {
    const [loading, setLoading] = useState(false);
    const [oauthConfig, setOAuthConfig] = useState({ // Состояние для настроек OAuth
        loading: true,
        enabled: false,
        providers: []
    });
    const { id: projectId } = useParams();
    const navigate = useNavigate(); // Для возможного редиректа

    // --- Добавлено: Загрузка конфигурации OAuth при монтировании ---
    useEffect(() => {
        const fetchOAuthConfig = async () => {
            if (!projectId || !isValidUUID(projectId)) {
                console.error("Invalid or missing project ID in URL");
                setOAuthConfig({ loading: false, enabled: false, providers: [] });
                // Можно показать сообщение об ошибке, если ID невалиден
                // message.error("Invalid project ID.");
                return;
            }
            try {
                const config = await getProjectOAuthConfig(projectId);
                setOAuthConfig({
                    loading: false,
                    enabled: config.oauth_enabled,
                    providers: config.enabled_providers || [] // Убедимся, что это массив
                });
            } catch (error) {
                console.error("Error fetching OAuth config:", error);
                message.error("Could not load login options.");
                setOAuthConfig({ loading: false, enabled: false, providers: [] });
            }
        };

        fetchOAuthConfig();
    }, [projectId]); // Зависимость от projectId

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
            }); // Тип user не нужен, saveTokens его больше не принимает

            // Отправляем сообщение родительскому окну
            window.parent.postMessage({
                type: "ATLAS_AUTH_SUCCESS",
                tokens: {
                    access_token: response.access_token,
                    refresh_token: response.refresh_token
                }
            }, "*"); // Укажите конкретный origin вместо "*" в production!

            // --- Опционально: Редирект после успешного входа ---
            // Нужно получить URL проекта с бэкенда или иметь его заранее
            // const projectUrl = await getProjectUrl(projectId); // Нужен такой API вызов
            // if (projectUrl) {
            //     window.parent.location.href = projectUrl;
            // } else {
            //     // Или редирект на дефолтную страницу
            //     navigate('/dashboard'); // Пример
            // }

        } catch (error) {
            console.error("Login error:", error);
            message.error(error.response?.data?.detail || error.message || "Login failed");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ padding: 20, maxWidth: 400, margin: "0 auto" }}>
            <h2>Login</h2>
            <Form
                name="login"
                layout="vertical"
                onFinish={onFinish}
                autoComplete="off"
            >
                {/* ... поля Email и Password ... */}
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

            {/* --- Добавлено: Условное отображение OAuth кнопок --- */}
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
            ) : null /* Не показываем ничего, если OAuth выключен или нет провайдеров */}
        </div>
    );
};

export default UserLoginEmbed;