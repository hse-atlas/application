import "normalize.css";
import { BrowserRouter as Router, Route, Routes, useLocation } from "react-router-dom";
import { useEffect } from "react";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Main from "./pages/Main";
import ProfileSettings from "./pages/ProfileSettings";
import Profile from "./pages/Profile";
import ProjectDetails from "./pages/ProjectDetails";
import UserLoginEmbed from "./components/UserLoginEmbed";
import UserRegisterEmbed from "./components/UserRegisterEmbed";
import tokenRefreshService from "./services/tokenRefreshService";
import tokenService from "./services/tokenService";

function AppContent() {
  const location = useLocation();

  useEffect(() => {
    // Проверка параметров URL
    const params = new URLSearchParams(location.search);
    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');

    if (accessToken && refreshToken) {
      // Добавляем детальное логирование для отладки
      console.log("OAuth tokens detected in URL:", {
        access_token_length: accessToken.length,
        access_token_starts_with: accessToken.substring(0, 10) + '...',
        refresh_token_length: refreshToken.length,
        refresh_token_starts_with: refreshToken.substring(0, 10) + '...'
      });

      try {
        // Сохранение токенов через сервис без указания типа пользователя
        // Тип будет определен автоматически из токена
        tokenService.saveTokens({
          access_token: accessToken,
          refresh_token: refreshToken
        });

        console.log("Tokens successfully saved to localStorage");

        // Удаление параметров из URL (чтобы они не остались в истории)
        const cleanUrl = window.location.pathname;
        window.history.replaceState({}, document.title, cleanUrl);

        // Перенаправляем на главную страницу для гарантированной активации
        // приложения после авторизации
        window.location.href = '/';
      } catch (error) {
        console.error("Error processing OAuth tokens:", error);
      }
      return; // Прерываем выполнение, так как будет перезагрузка
    }

    // Проверка наличия токена в localStorage для запуска сервиса обновления
    const isEmbedPage = location.pathname.startsWith('/embed/login/') ||
      location.pathname.startsWith('/embed/register/');

    // Используем метод проверки аутентификации из сервиса
    if (tokenService.isAuthenticated() && !isEmbedPage) {
      console.log("User is authenticated, starting token refresh service");
      tokenRefreshService.start();
    } else {
      console.log("User is not authenticated or on embed page, not starting token refresh service");

      // Если мы на странице логина или регистрации, убедимся что токены очищены
      if (location.pathname === '/login' || location.pathname === '/register') {
        tokenService.clearTokens();
      }
    }

    return () => {
      tokenRefreshService.stop();
    };
  }, [location.pathname, location.search]); // Наблюдаем за URL и параметрами

  return (
    <Routes>
      <Route path="/" element={<Main />} />
      <Route path="/project/:id" element={<ProjectDetails />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/profile" element={<Profile />} />
      <Route path="/settings" element={<ProfileSettings />} />
      <Route path="/embed/login/:id" element={<UserLoginEmbed />} />
      <Route path="/embed/register/:id" element={<UserRegisterEmbed />} />
    </Routes>
  );
}

function App() {
  return (
    <Router>
      <AppContent />  {/* Теперь useLocation работает корректно */}
    </Router>
  );
}

export default App;