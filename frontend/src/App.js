import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { ThemeProvider } from "./components/ThemeProvider";
import Register from "./components/register";
import Login from "./components/login";
import Dashboard from "./components/dashboard";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import './styles/theme.css';
import './styles/components.css';
import "@fortawesome/fontawesome-free/css/all.min.css";

// Import admin components
import CompanyRegistration from "./components/CompanyRegistration";
import AdminLogin from "./components/AdminLogin";
import AdminDashboard from "./components/AdminDashboard";
import CompaniesList from "./components/CompaniesList";

// Authentication protection wrappers
const ProtectedRoute = ({ children }) => {
  const token = localStorage.getItem('token');
  return token ? children : <Navigate to="/login" />;
};

const AdminProtectedRoute = ({ children }) => {
  const adminToken = localStorage.getItem('admin_token');
  const isAdmin = localStorage.getItem('is_admin') === 'true';
  return (adminToken && isAdmin) ? children : <Navigate to="/admin/login" />;
};

function App() {
  return (
    <ThemeProvider>
      <Router>
        <div>
          <Routes>
            {/* Default route - redirect to login */}
            <Route path="/" element={<Navigate to="/login" />} />
            
            {/* User routes */}
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/dashboard" element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            } />
            
            {/* Admin routes */}
            <Route path="/admin/register" element={<CompanyRegistration />} />
            <Route path="/admin/login" element={<AdminLogin />} />
            <Route path="/admin/dashboard" element={
              <AdminProtectedRoute>
                <AdminDashboard />
              </AdminProtectedRoute>
            } />
            <Route path="/admin/companies" element={<CompaniesList />} />
            <Route path="/admin/companies/:domain" element={
              <AdminProtectedRoute>
                <AdminDashboard />
              </AdminProtectedRoute>
            } />
          </Routes>
        </div>
        <ToastContainer 
          position="top-right" 
          autoClose={3000} 
          hideProgressBar={false}
          newestOnTop
          closeOnClick
          rtl={false}
          pauseOnFocusLoss
          draggable
          pauseOnHover
          theme="colored"
        />
      </Router>
    </ThemeProvider>
  );
}

export default App;