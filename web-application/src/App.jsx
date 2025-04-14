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

function AppContent() {  // <-- Новый компонент внутри Router
  const location = useLocation();

  useEffect(() => {
    const isEmbedPage = location.pathname.startsWith('/embed/login/') ||
      location.pathname.startsWith('/embed/register/');

    const accessToken = localStorage.getItem("access_token");
    if (accessToken && !isEmbedPage) {
      tokenRefreshService.start();
    }

    return () => {
      tokenRefreshService.stop();
    };
  }, [location.pathname]);

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