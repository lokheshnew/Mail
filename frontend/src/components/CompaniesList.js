import React, { useState, useEffect } from "react";
import axios from "axios";
import { useNavigate, Link } from "react-router-dom";
import "./CompaniesList.css";
import { API_BASE_URL } from "../config";
import {
  FaBuilding,
  FaGlobe,
  FaUser,
  FaCalendarAlt,
  FaPlus,
} from "react-icons/fa";

function CompaniesList() {
  const [companies, setCompanies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const navigate = useNavigate();

  // Fetch companies on component mount
  useEffect(() => {
    fetchCompanies();
  }, []);

  const fetchCompanies = async () => {
    try {
      // Get the admin token if available
      const adminToken = localStorage.getItem("admin_token");
      const headers = adminToken ? { "MAIL-KEY": adminToken } : {};

      // ✅ CORRECT ENDPOINT - Using /company/companies
      const res = await axios.get(`${API_BASE_URL}/company/companies`, {
        headers,
      });
      setCompanies(res.data.companies || []);
      setLoading(false);
    } catch (error) {
      console.error("Error fetching companies:", error);
      setError("Failed to load companies. Please try again.");

      // Simulated data for demo purposes if API fails
      setCompanies([
        {
          id: "acme_inc",
          name: "ACME Inc",
          domain: "acme.com",
          admin_name: "John Admin",
          created_at: "Wed Jun 14 15:23:40 2023",
          status: "active",
        },
        {
          id: "beta_corp",
          name: "Beta Corporation",
          domain: "betacorp.com",
          admin_name: "Sarah Manager",
          created_at: "Thu Jun 15 09:15:22 2023",
          status: "active",
        },
        {
          id: "gamma_llc",
          name: "Gamma LLC",
          domain: "gammallc.com",
          admin_name: "Robert Director",
          created_at: "Fri Jun 16 11:45:10 2023",
          status: "inactive",
        },
      ]);
      setLoading(false);
    }
  };

  const handleCompanyClick = (domain) => {
    // Navigate to company details or prompt for admin login
    navigate(`/admin/companies/${domain}`);
  };

  return (
    <div className="companies-layout">
      <div className="back-navigation">
        <Link to="/login" className="back-button">
          ← Back to Login
        </Link>
      </div>

      <div className="companies-container">
        <div className="companies-header">
          <h1>Registered Companies</h1>
          <Link to="/admin/register" className="add-company-button">
            <FaPlus /> Register New Company
          </Link>
        </div>

        {loading ? (
          <div className="loading-container">
            <div className="loading-spinner"></div>
            <p>Loading companies...</p>
          </div>
        ) : error ? (
          <div className="error-message">
            <p>{error}</p>
            <button onClick={fetchCompanies}>Try Again</button>
          </div>
        ) : (
          <div className="companies-grid">
            {companies.length === 0 ? (
              <div className="no-companies">
                <FaBuilding className="icon" />
                <h2>No Companies Found</h2>
                <p>
                  Be the first to register a company domain and start managing
                  your organization's email system
                </p>
                <Link to="/admin/register" className="register-button">
                  Register Your Company
                </Link>
              </div>
            ) : (
              companies.map((company, index) => (
                <div
                  key={company.id}
                  className={`company-card ${company.status} animate-fadeIn`}
                  onClick={() => handleCompanyClick(company.domain)}
                  style={{ animationDelay: `${index * 0.1}s` }}
                >
                  <div className="company-header">
                    <h2>{company.name}</h2>
                    <span
                      className={`status-indicator ${company.status}`}
                    ></span>
                  </div>

                  <div className="company-info">
                    <div className="info-item">
                      <FaGlobe className="info-icon" />
                      <p>{company.domain}</p>
                    </div>

                    <div className="info-item">
                      <FaUser className="info-icon" />
                      <p>{company.admin_name}</p>
                    </div>

                    <div className="info-item">
                      <FaCalendarAlt className="info-icon" />
                      <p>
                        Registered:{" "}
                        {new Date(company.created_at).toLocaleDateString()}
                      </p>
                    </div>
                  </div>

                  {/* <div className="company-actions">
                    <button className="login-button">
                      Access Admin Panel
                    </button>
                  </div> */}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default CompaniesList;
