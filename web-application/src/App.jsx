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

function AppContent() {  // <-- Компонент внутри Router
  const location = useLocation();

  useEffect(() => {
    // Проверка параметров URL
    const params = new URLSearchParams(location.search);
    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');

    if (accessToken && refreshToken) {
      // Сохранение токенов в localStorage
      localStorage.setItem('access_token', accessToken);
      localStorage.setItem('refresh_token', refreshToken);

      // Удаление параметров из URL (чтобы они не остались в истории)
      const cleanUrl = window.location.pathname;
      window.history.replaceState({}, document.title, cleanUrl);

      // Запуск сервиса обновления токенов
      tokenRefreshService.start();
    } else {
      // Проверка наличия токена в localStorage для запуска сервиса обновления
      const isEmbedPage = location.pathname.startsWith('/embed/login/') ||
        location.pathname.startsWith('/embed/register/');

      const storedAccessToken = localStorage.getItem("access_token");
      if (storedAccessToken && !isEmbedPage) {
        tokenRefreshService.start();
      }
    }

    return () => {
      tokenRefreshService.stop();
    };
  }, [location.pathname, location.search]); // Добавлен location.search для отслеживания параметров

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