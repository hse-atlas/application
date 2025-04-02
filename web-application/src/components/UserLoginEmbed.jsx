// UserLoginEmbed.jsx
import React, { useState, useEffect } from "react";
import { Form, Input, Button, message } from "antd";
import { useParams } from "react-router-dom";
import { loginUser } from "../api";

const UserLoginEmbed = () => {
    const [loading, setLoading] = useState(false);
    const { id: projectId } = useParams();

    const onFinish = async (values) => {
        setLoading(true);
        try {
            const response = await loginUser(projectId, {
                email: values.email,
                password: values.password,
            });

            window.parent.postMessage({
                type: "ATLAS_AUTH_SUCCESS",
                tokens: {
                    access_token: response.access_token,
                    refresh_token: response.refresh_token
                }
            }, "*");

        } catch (error) {
            message.error(error.message);
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

                <Form.Item>
                    <Button type="primary" htmlType="submit" block loading={loading}>
                        Login
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default UserLoginEmbed;