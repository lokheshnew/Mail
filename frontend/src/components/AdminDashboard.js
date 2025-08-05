import React, { useState, useEffect } from "react";
import axios from "axios";
import { useNavigate, Link } from "react-router-dom";
import "./AdminDashboard.css";
import { API_BASE_URL } from "../config";
import { FaUsers, FaEnvelope, FaChartBar, FaSignOutAlt, FaCog, FaSpinner } from "react-icons/fa";

function AdminDashboard() {
  const [domainUsers, setDomainUsers] = useState([]);
  const [domainStats, setDomainStats] = useState({
    total_users: 0,
    active_users: 0,
    total_emails: 0,
    storage_used: { used_mb: 0, total_mb: 0, percentage: 0 }
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeSection, setActiveSection] = useState("users");
  const [dataLoading, setDataLoading] = useState(false);

  const navigate = useNavigate();
  
  // Get admin information from localStorage
  const adminEmail = localStorage.getItem("admin_email");
  const adminDomain = localStorage.getItem("admin_domain");
  const adminToken = localStorage.getItem("admin_token");
  
  // Check if user is logged in as admin
  useEffect(() => {
    if (!adminToken || !adminEmail || !adminEmail.startsWith('admin@')) {
      navigate("/admin/login");
    } else {
      fetchDomainUsers();
      fetchDomainStats();
    }
  }, [adminToken, adminEmail, navigate]);
  
  // Fetch users of this domain
  const fetchDomainUsers = async () => {
    setDataLoading(true);
    setError("");
    
    try {
      // ✅ CORRECT ENDPOINT - Using /company/domain_users
      const response = await axios.get(`${API_BASE_URL}/company/domain_users/${adminDomain}`, {
        headers: { 
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.data && response.data.users) {
        setDomainUsers(response.data.users);
      } else {
        setDomainUsers([]);
      }
      
    } catch (error) {
      console.error("Error fetching domain users:", error);
      
      let errorMessage = "Failed to load users. ";
      
      if (error.response?.status === 401) {
        errorMessage = "Authentication failed. Please login again.";
        handleLogout();
        return;
      } else if (error.response?.status === 403) {
        errorMessage = "Access denied. Admin privileges required.";
      } else if (error.response?.status === 404) {
        errorMessage = "Domain not found.";
      } else if (error.response?.data?.error) {
        errorMessage = error.response.data.error;
      } else {
        errorMessage += "Please try again.";
      }
      
      setError(errorMessage);
      setDomainUsers([]);
    } finally {
      setDataLoading(false);
      setLoading(false);
    }
  };
  
  // Fetch domain statistics
  const fetchDomainStats = async () => {
    try {
      // ✅ CORRECT ENDPOINT - Using /company/domain_stats
      const response = await axios.get(`${API_BASE_URL}/company/domain_stats/${adminDomain}`, {
        headers: { 
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.data && response.data.stats) {
        setDomainStats(response.data.stats);
      } else {
        // Set default stats if no data
        setDomainStats({
          total_users: 0,
          active_users: 0,
          total_emails: 0,
          storage_used: { used_mb: 0, total_mb: 100, percentage: 0 }
        });
      }
      
    } catch (error) {
      console.error("Error fetching domain stats:", error);
      
      // Set fallback stats based on user data we have
      const userCount = domainUsers.length;
      const activeCount = domainUsers.filter(user => user.status === 'active').length;
      
      setDomainStats({
        total_users: userCount,
        active_users: activeCount,
        total_emails: 0, // Will be updated when backend implements this
        storage_used: { used_mb: 0, total_mb: 100, percentage: 0 }
      });
    }
  };
  
  // Update stats when users change
  useEffect(() => {
    if (domainUsers.length > 0) {
      const totalUsers = domainUsers.length;
      const activeUsers = domainUsers.filter(user => user.status === 'active').length;
      
      setDomainStats(prev => ({
        ...prev,
        total_users: totalUsers,
        active_users: activeUsers
      }));
    }
  }, [domainUsers]);
  
  const handleLogout = () => {
    // Clear admin session
    localStorage.removeItem("admin_token");
    localStorage.removeItem("admin_email");
    localStorage.removeItem("admin_username");
    localStorage.removeItem("admin_id");
    localStorage.removeItem("admin_domain");
    localStorage.removeItem("is_admin");
    
    navigate("/admin/login");
  };

  const refreshData = async () => {
    setLoading(true);
    await Promise.all([fetchDomainUsers(), fetchDomainStats()]);
    setLoading(false);
  };

  const formatDate = (dateString) => {
    if (!dateString) return "Never";
    try {
      return new Date(dateString).toLocaleString();
    } catch (error) {
      return "Invalid date";
    }
  };

  const getInitials = (email) => {
    if (!email) return "U";
    return email.split("@")[0].charAt(0).toUpperCase();
  };

  const handleAddUser = () => {
    // TODO: Implement add user functionality
    alert("Add user functionality will be implemented soon!");
  };

  const handleEditUser = (user) => {
    // TODO: Implement edit user functionality
    alert(`Edit user functionality for ${user.email} will be implemented soon!`);
  };

  const handleDeleteUser = (user) => {
    // TODO: Implement delete user functionality
    if (user.email === adminEmail) {
      alert("Cannot delete admin account!");
      return;
    }
    
    if (window.confirm(`Are you sure you want to delete user ${user.email}?`)) {
      alert("Delete user functionality will be implemented soon!");
    }
  };

  return (
    <div className="admin-dashboard">
      <div className="admin-sidebar">
        <div className="admin-profile">
          <div className="admin-avatar">
            {getInitials(adminEmail)}
          </div>
          <div className="admin-info">
            <h3>Admin Panel</h3>
            <p>{adminEmail}</p>
          </div>
        </div>
        
        <nav className="admin-nav">
          <ul>
            <li 
              className={activeSection === "users" ? "active" : ""} 
              onClick={() => setActiveSection("users")}
            >
              <FaUsers /> Users
            </li>
            <li 
              className={activeSection === "emails" ? "active" : ""} 
              onClick={() => setActiveSection("emails")}
            >
              <FaEnvelope /> Emails
            </li>
            <li 
              className={activeSection === "stats" ? "active" : ""} 
              onClick={() => setActiveSection("stats")}
            >
              <FaChartBar /> Statistics
            </li>
            <li 
              className={activeSection === "settings" ? "active" : ""} 
              onClick={() => setActiveSection("settings")}
            >
              <FaCog /> Settings
            </li>
            <li onClick={handleLogout}>
              <FaSignOutAlt /> Logout
            </li>
          </ul>
        </nav>
        
        <div className="domain-info">
          <h4>Domain</h4>
          <p>{adminDomain}</p>
        </div>
      </div>
      
      <div className="admin-content">
        <header className="admin-header">
          <h2>
            {activeSection === "users" && "Domain Users"}
            {activeSection === "emails" && "Email Management"}
            {activeSection === "stats" && "Domain Statistics"}
            {activeSection === "settings" && "Domain Settings"}
          </h2>
          <div className="header-actions">
            {activeSection === "users" && (
              <button className="add-user-btn" onClick={handleAddUser}>
                Add New User
              </button>
            )}
            <button className="refresh-btn" onClick={refreshData} disabled={loading}>
              {loading ? <FaSpinner className="spinning" /> : "Refresh"}
            </button>
          </div>
        </header>
        
        <div className="admin-stats-overview">
          <div className="stat-card">
            <h3>Total Users</h3>
            <p className="stat-value">{domainStats.total_users}</p>
            <p className="stat-detail">Registered users</p>
          </div>
          <div className="stat-card">
            <h3>Active Users</h3>
            <p className="stat-value">{domainStats.active_users}</p>
            <p className="stat-detail">Currently active</p>
          </div>
          <div className="stat-card">
            <h3>Emails</h3>
            <p className="stat-value">{domainStats.total_emails}</p>
            <p className="stat-detail">Total messages</p>
          </div>
          <div className="stat-card">
            <h3>Storage</h3>
            <p className="stat-value">{domainStats.storage_used.used_mb} MB</p>
            <div className="storage-bar">
              <div 
                className="storage-used" 
                style={{ width: `${domainStats.storage_used.percentage}%` }}
              ></div>
            </div>
            <p className="stat-detail">
              {domainStats.storage_used.percentage}% of {domainStats.storage_used.total_mb} MB
            </p>
          </div>
        </div>
        
        {error && (
          <div className="error-message">
            <p>{error}</p>
            <button onClick={refreshData}>Retry</button>
          </div>
        )}
        
        {activeSection === "users" && (
          <div className="section-content">
            <div className="users-list">
              <table>
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Last Login</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {dataLoading ? (
                    <tr>
                      <td colSpan="6" className="loading">
                        <FaSpinner className="spinning" /> Loading users...
                      </td>
                    </tr>
                  ) : domainUsers.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="no-data">
                        {error ? "Failed to load users" : "No users found for this domain"}
                      </td>
                    </tr>
                  ) : (
                    domainUsers.map((user, index) => (
                      <tr key={user.user_id || index} className={user.email === adminEmail ? "admin-row" : ""}>
                        <td>{user.username || "N/A"}</td>
                        <td>{user.email}</td>
                        <td>
                          <span className={`status-badge ${user.status || 'active'}`}>
                            {user.status || 'active'}
                          </span>
                        </td>
                        <td>{formatDate(user.created_at)}</td>
                        <td>{formatDate(user.last_login)}</td>
                        <td>
                          <div className="action-buttons">
                            <button 
                              className="edit-btn"
                              onClick={() => handleEditUser(user)}
                            >
                              Edit
                            </button>
                            {user.email !== adminEmail && (
                              <button 
                                className="delete-btn"
                                onClick={() => handleDeleteUser(user)}
                              >
                                Delete
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
        
        {activeSection === "emails" && (
          <div className="section-content">
            <div className="placeholder-text">
              <h3>Email Management</h3>
              <p>Email management features will be implemented here.</p>
              <p>This will include:</p>
              <ul>
                <li>Monitor email traffic</li>
                <li>View email logs</li>
                <li>Manage blocked senders</li>
                <li>Email quotas and limits</li>
              </ul>
            </div>
          </div>
        )}
        
        {activeSection === "stats" && (
          <div className="section-content">
            <div className="stats-details">
              <h3>Detailed Statistics</h3>
              <div className="stats-grid">
                <div className="stat-item">
                  <h4>User Statistics</h4>
                  <p>Total Users: {domainStats.total_users}</p>
                  <p>Active Users: {domainStats.active_users}</p>
                  <p>Inactive Users: {domainStats.total_users - domainStats.active_users}</p>
                </div>
                <div className="stat-item">
                  <h4>Email Statistics</h4>
                  <p>Total Emails: {domainStats.total_emails}</p>
                  <p>Average per User: {domainStats.total_users > 0 ? Math.round(domainStats.total_emails / domainStats.total_users) : 0}</p>
                </div>
                <div className="stat-item">
                  <h4>Storage Statistics</h4>
                  <p>Used: {domainStats.storage_used.used_mb} MB</p>
                  <p>Total: {domainStats.storage_used.total_mb} MB</p>
                  <p>Percentage: {domainStats.storage_used.percentage}%</p>
                </div>
              </div>
            </div>
          </div>
        )}
        
        {activeSection === "settings" && (
          <div className="section-content">
            <div className="domain-settings">
              <h3>Domain Settings</h3>
              <form className="settings-form">
                <div className="form-group">
                  <label>Domain Name</label>
                  <input type="text" value={adminDomain} disabled />
                </div>
                <div className="form-group">
                  <label>Storage Limit per User (MB)</label>
                  <input type="number" defaultValue="100" />
                </div>
                <div className="form-group">
                  <label>Maximum Users</label>
                  <input type="number" defaultValue="50" />
                </div>
                <div className="form-group">
                  <label>Welcome Email Template</label>
                  <textarea 
                    rows="6" 
                    defaultValue={`Hello {username},\n\nWelcome to ${adminDomain} Mail!\n\nYour account has been successfully created. You can now send and receive emails using your new address: {email}.\n\nBest regards,\nThe ${adminDomain} Team`}
                  ></textarea>
                </div>
                <button type="submit" className="save-settings-btn">Save Settings</button>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default AdminDashboard;