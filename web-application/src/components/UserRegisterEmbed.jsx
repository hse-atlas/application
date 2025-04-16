// UserRegisterEmbed.jsx
import React, { useState, useEffect } from "react";
import { Form, Input, Button, message } from "antd";
import { useParams } from "react-router-dom";
import { registerUser, isValidUUID } from "../api";
import tokenService from "../services/tokenService";

const UserRegisterEmbed = () => {
    const [loading, setLoading] = useState(false);
    const { id: projectId } = useParams();

    const onFinish = async (values) => {
        setLoading(true);
        try {
            if (!isValidUUID(projectId)) {
                throw new Error("Invalid project ID format");
            }

            const response = await registerUser(projectId, {
                login: values.username,
                email: values.email,
                password: values.password,
            });

            console.log('Server response:', response); // Добавьте для отладки

            // Проверяем наличие user_id в ответе (с учетом возможных вариантов именования)
            const userId = response.user_id || response.userId || response.id;
            if (!userId) {
                throw new Error("User ID not found in server response");
            }

            window.parent.postMessage({
                type: "ATLAS_REGISTER_SUCCESS",
                user: {
                    id: userId,  // Используем извлеченный ID
                    email: values.email,
                    username: values.username
                }
            }, "*");

        } catch (error) {
            console.error('Registration error:', error);
            message.error(error.message || "Registration failed");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ padding: 20, maxWidth: 400, margin: "0 auto" }}>
            <Form
                name="register"
                layout="vertical"
                onFinish={onFinish}
                autoComplete="off"
            >
                <Form.Item
                    name="username"
                    label="Username"
                    rules={[{ required: true }]}
                >
                    <Input />
                </Form.Item>

                <Form.Item
                    name="email"
                    label="Email"
                    rules={[{ type: "email", required: true }]}
                >
                    <Input />
                </Form.Item>

                <Form.Item
                    name="password"
                    label="Password"
                    rules={[{ required: true }]}
                >
                    <Input.Password />
                </Form.Item>

                <Form.Item
                    name="confirm"
                    label="Confirm Password"
                    dependencies={["password"]}
                    rules={[{ required: true }]}
                >
                    <Input.Password />
                </Form.Item>

                <Form.Item>
                    <Button type="primary" htmlType="submit" block loading={loading}>
                        Register
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default UserRegisterEmbed;