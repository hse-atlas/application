import React from "react";
import ReactDOM from "react-dom";
import { Provider } from "react-redux";
import store from "./store/store";
import App from "./App";
import { checkAndRefreshTokenIfNeeded } from "./api";

// Добавляем возможность проверять токены из консоли браузера
window.debugToken = () => {
  const token = localStorage.getItem('access_token');
  if (!token) {
    console.log('%c[Token Debug] ❌ No token found', 'color: red');
    return;
  }

  try {
    // Декодируем токен
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64).split('').map(c => {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join('')
    );

    const payload = JSON.parse(jsonPayload);
    const exp = payload.exp;
    const currentTime = Math.floor(Date.now() / 1000);
    const expiresIn = exp - currentTime;

    console.log('%c[Token Debug] 🔎 Token info:', 'font-weight: bold; color: #1890ff');
    console.log('- Expires:', new Date(exp * 1000).toLocaleString());
    console.log('- Expires in:', Math.floor(expiresIn / 60), 'minutes,', expiresIn % 60, 'seconds');
    console.log('- User ID:', payload.sub);
    console.log('- Token type:', payload.type);
    console.log('- Full payload:', payload);

    if (expiresIn < 300) {
      console.log('%c[Token Debug] ⚠️ Token expires soon! Running refresh...', 'color: orange');
      checkAndRefreshTokenIfNeeded().then(() => {
        console.log('%c[Token Debug] ✅ Token refresh process completed', 'color: green');
      });
    } else {
      console.log('%c[Token Debug] ✅ Token is valid for a while', 'color: green');
    }
  } catch (error) {
    console.log('%c[Token Debug] ❌ Error decoding token', 'color: red', error);
  }
};

console.log('[App] To debug tokens, run window.debugToken() in the console');

ReactDOM.render(
  <Provider store={store}>
    <App />
  </Provider>,
  document.getElementById("root")
);