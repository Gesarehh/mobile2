import {BrowserRouter, Routes, Route} from 'react-router-dom';
import  Login from './pages/Login';
import  Dashboard from './pages/Dashboard';
import  Users from './pages/Users';
import PrivateRoute from './components/PrivateRoute';
import { AuthProvider } from './context/AuthContext';

export default function App() {
  return (
    <BrowserRouter>
    <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route  element={<PrivateRoute />} />
          <Route path="/register" element={<Dashboard />} />
          <Route path="/Users" element={<Users />} />
        </Routes>
    </AuthProvider>
    </BrowserRouter>
  );
}