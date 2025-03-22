import "normalize.css";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Main from "./pages/Main";
import ProfileSettings from "./pages/ProfileSettings";
import Profile from "./pages/Profile";
import ProjectDetails from "./pages/ProjectDetails";
import UserRegister from "./pages/UserRegister";
import UserLogin from "./pages/UserLogin";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Main />} />
        <Route path="/project/:id" element={<ProjectDetails />} />{" "}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/settings" element={<ProfileSettings />} />
        <Route path="/userRegister/:id" element={<UserRegister />} />
        <Route path="/userLogin/:id" element={<UserLogin />} />
      </Routes>
    </Router>
  );
}

export default App;
