import React, { useState, useEffect, useCallback } from "react";
import axios from "axios";
import { useNavigate, Link } from "react-router-dom";
import "./login.css";
import { API_BASE_URL } from "../config";
import { FaBuilding, FaGlobe, FaUser, FaCheck, FaTimes, FaSpinner } from "react-icons/fa";

function CompanyRegistration() {
  const [companyName, setCompanyName] = useState("");
  const [domain, setDomain] = useState("");
  const [adminName, setAdminName] = useState("");
  const [message, setMessage] = useState("");
  const [isChecking, setIsChecking] = useState(false);
  const [isDomainAvailable, setIsDomainAvailable] = useState(null);
  const [isRegistering, setIsRegistering] = useState(false);
  const [checkTimeoutId, setCheckTimeoutId] = useState(null);

  const navigate = useNavigate();

  // Debounced domain availability check
  const checkDomainAvailability = useCallback(async (domainToCheck) => {
    if (!domainToCheck || !domainToCheck.includes('.')) {
      setMessage("Please enter a valid domain (e.g., company.com)");
      setIsDomainAvailable(null);
      return;
    }

    setIsChecking(true);
    setMessage("");
    
    try {
      // ✅ CORRECT ENDPOINT - Using /company/check_domain
      const res = await axios.post(`${API_BASE_URL}/company/check_domain`, { 
        domain: domainToCheck.trim().toLowerCase() 
      });
      
      const available = res.data.available;
      setIsDomainAvailable(available);
      
      if (available) {
        setMessage(`✅ Domain ${domainToCheck} is available!`);
      } else {
        setMessage(`❌ Domain ${domainToCheck} is already registered.`);
      }
    } catch (error) {
      console.error("Domain check error:", error);
      setMessage("Error checking domain availability. Please try again.");
      setIsDomainAvailable(null);
    } finally {
      setIsChecking(false);
    }
  }, []);

  // Handle domain input change with proper debouncing
  const handleDomainChange = (e) => {
    const value = e.target.value.trim();
    setDomain(value);
    setIsDomainAvailable(null);
    setMessage("");
    
    // Clear existing timeout
    if (checkTimeoutId) {
      clearTimeout(checkTimeoutId);
    }
    
    // Only check if the domain looks complete (has at least one dot)
    if (value && value.includes('.') && value.length > 3) {
      const newTimeoutId = setTimeout(() => {
        checkDomainAvailability(value);
      }, 800);
      setCheckTimeoutId(newTimeoutId);
    }
  };

  // Manual domain check (when user clicks out of field)
  const handleDomainBlur = () => {
    if (domain && domain.includes('.') && !isChecking) {
      checkDomainAvailability(domain);
    }
  };

  // Clean up timeout on unmount
  useEffect(() => {
    return () => {
      if (checkTimeoutId) {
        clearTimeout(checkTimeoutId);
      }
    };
  }, [checkTimeoutId]);

  const handleCompanyRegistration = async (e) => {
    e.preventDefault();
    
    // Validation
    if (!companyName.trim()) {
      setMessage("Company name is required");
      return;
    }
    
    if (!domain.trim()) {
      setMessage("Domain is required");
      return;
    }
    
    if (!adminName.trim()) {
      setMessage("Admin name is required");
      return;
    }
    
    if (!domain.includes('.')) {
      setMessage("Please enter a valid domain (e.g., company.com)");
      return;
    }
    
    setIsRegistering(true);
    setMessage("");
    
    try {
      // Final domain availability check before registration
      const domainCheckRes = await axios.post(`${API_BASE_URL}/company/check_domain`, { 
        domain: domain.trim().toLowerCase() 
      });
      
      if (!domainCheckRes.data.available) {
        setMessage(`❌ Domain ${domain} is not available. Please choose a different domain.`);
        setIsDomainAvailable(false);
        setIsRegistering(false);
        return;
      }
      
      // Proceed with registration
      // ✅ CORRECT ENDPOINT - Using /company/register_company
      const res = await axios.post(`${API_BASE_URL}/company/register_company`, {
        company_name: companyName.trim(),
        domain: domain.trim().toLowerCase(),
        admin_name: adminName.trim()
      });
      
      setMessage("✅ Company registered successfully!");
      
      // Show success message with admin credentials
      const adminDetails = `Company: ${res.data.company.name}
Domain: ${res.data.company.domain}
Admin Email: ${res.data.company.admin_email}
Admin Password: ${res.data.company.admin_password}`;
      
      alert(`🎉 Company registered successfully!\n\n📧 Admin account details:\n${adminDetails}\n\n⚠️ Please save these credentials securely. You won't see them again!`);
      
      // Redirect to admin companies list
      navigate("/admin/companies");
      
    } catch (error) {
      console.error("Registration error:", error);
      
      let errorMessage = "Registration failed. Please try again.";
      
      if (error.response?.data?.error) {
        errorMessage = error.response.data.error;
      } else if (error.response?.status === 409) {
        errorMessage = `Domain ${domain} is already registered. Please choose a different domain.`;
        setIsDomainAvailable(false);
      } else if (error.response?.status === 400) {
        errorMessage = "Invalid input. Please check your details and try again.";
      } else if (error.response?.status === 500) {
        errorMessage = "Server error. Please try again later.";
      }
      
      setMessage(`❌ ${errorMessage}`);
    } finally {
      setIsRegistering(false);
    }
  };

  // Domain validation helper
  const isValidDomain = (domain) => {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.[a-zA-Z]{2,}$/;
    return domainRegex.test(domain);
  };

  // Get domain status icon
  const getDomainStatusIcon = () => {
    if (isChecking) {
      return <FaSpinner className="domain-status checking" />;
    }
    if (isDomainAvailable === true) {
      return <FaCheck className="domain-status available" />;
    }
    if (isDomainAvailable === false) {
      return <FaTimes className="domain-status unavailable" />;
    }
    return null;
  };

  return (
    <div className="auth-layout">
      <div className="auth-container company-registration">
        <div className="auth-header">
          <div className="auth-logo">
            🏢
          </div>
          <h2 className="auth-title">Register Company</h2>
          <p className="auth-subtitle">Create a custom email domain for your organization</p>
        </div>
        
        <div className="auth-body">
          <form onSubmit={handleCompanyRegistration} className="auth-form">
            <div className="input-wrapper">
              <input
                type="text"
                placeholder="Company Name"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                required
                maxLength={100}
              />
              <FaBuilding className="input-icon" />
            </div>

            <div className="input-wrapper domain-input">
              <input
                type="text"
                placeholder="Domain (e.g., company.com)"
                value={domain}
                onChange={handleDomainChange}
                onBlur={handleDomainBlur}
                required
                maxLength={50}
                style={{
                  paddingRight: '80px' // Make room for both icons
                }}
              />
              <FaGlobe className="input-icon" style={{ right: '50px' }} />
              {getDomainStatusIcon()}
            </div>

            <div className="input-wrapper">
              <input
                type="text"
                placeholder="Admin Name"
                value={adminName}
                onChange={(e) => setAdminName(e.target.value)}
                required
                maxLength={50}
              />
              <FaUser className="input-icon" />
            </div>

            <button 
              type="submit" 
              disabled={isRegistering || isChecking || !isDomainAvailable}
              className={(!isDomainAvailable || isRegistering || isChecking) ? 'button-disabled' : ''}
            >
              {isRegistering ? (
                <>
                  <FaSpinner className="animate-spin" />
                  Registering Company...
                </>
              ) : (
                'Register Company'
              )}
            </button>
          </form>

          {message && (
            <div className={`message ${isDomainAvailable === false ? 'error' : ''}`}>
              {message}
            </div>
          )}
        </div>

        <div className="auth-footer">
          <div className="auth-options">
            <p>
              Already registered?{" "}
              <Link to="/admin/login" className="login-link">
                Admin Login
              </Link>
            </p>
            
            <div className="back-to-main">
              <Link to="/login" className="main-link">
                ← Back to Main Login
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CompanyRegistration;