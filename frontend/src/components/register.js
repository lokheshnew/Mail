import React, { useState } from "react";
import axios from "axios";
import { useNavigate, Link } from "react-router-dom";
import "./login.css";
import { API_BASE_URL } from "../config";
import { FaUser, FaEnvelope, FaEye, FaEyeSlash, FaSpinner } from "react-icons/fa";

function Register() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);

  const navigate = useNavigate();

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const toggleConfirmPasswordVisibility = () => {
    setShowConfirmPassword(!showConfirmPassword);
  };

  const validateForm = () => {
    if (!username.trim()) {
      setMessage("❌ Username is required");
      return false;
    }

    if (username.trim().length < 2) {
      setMessage("❌ Username must be at least 2 characters long");
      return false;
    }

    if (!email.trim()) {
      setMessage("❌ Email is required");
      return false;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      setMessage("❌ Please enter a valid email address");
      return false;
    }

    if (!password) {
      setMessage("❌ Password is required");
      return false;
    }

    if (password.length < 6) {
      setMessage("❌ Password must be at least 6 characters long");
      return false;
    }

    if (password !== confirmPassword) {
      setMessage("❌ Passwords do not match");
      return false;
    }

    return true;
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setMessage("");

    if (!validateForm()) {
      return;
    }

    setIsRegistering(true);

    try {
      // ✅ CORRECT ENDPOINT - Using /auth/register
      const res = await axios.post(`${API_BASE_URL}/auth/register`, {
        username: username.trim(),
        email: email.trim().toLowerCase(),
        password: password
      });

      setMessage("✅ Registration successful! Redirecting to login...");
      
      // Redirect to login page with success message
      setTimeout(() => {
        navigate("/login", { 
          state: { 
            registrationSuccess: true,
            message: "Registration successful! Please login with your credentials.",
            email: email.trim().toLowerCase()
          }
        });
      }, 1500);

    } catch (error) {
      console.error("Registration error:", error);
      
      let errorMessage = "Registration failed. Please try again.";
      
      if (error.response?.data?.error) {
        errorMessage = error.response.data.error;
      } else if (error.response?.status === 400) {
        errorMessage = "Invalid input. Please check your details and try again.";
      } else if (error.response?.status === 409) {
        errorMessage = "User already exists with this email address.";
      } else if (error.response?.status === 500) {
        errorMessage = "Server error. Please try again later.";
      } else if (error.code === 'NETWORK_ERROR') {
        errorMessage = "Network error. Please check your connection and try again.";
      }
      
      setMessage("❌ " + errorMessage);
    } finally {
      setIsRegistering(false);
    }
  };

  return (
    <div className="auth-layout">
      <div className="auth-container">
        <div className="auth-header">
          <div className="auth-logo">
            📧
          </div>
          <h2 className="auth-title">Create Account</h2>
          <p className="auth-subtitle">Join our mail service and start communicating</p>
        </div>
        
        <div className="auth-body">
          <form onSubmit={handleRegister} className="auth-form">
            <div className="input-wrapper">
              <input
                type="text"
                placeholder="Full Name"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                disabled={isRegistering}
                maxLength={50}
              />
              <FaUser className="input-icon" />
            </div>

            <div className="input-wrapper">
              <input
                type="email"
                placeholder="Email Address"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={isRegistering}
                maxLength={100}
              />
              <FaEnvelope className="input-icon" />
            </div>

            <div className="input-wrapper">
              <input
                type={showPassword ? "text" : "password"}
                placeholder="Password (min 6 characters)"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={isRegistering}
                minLength={6}
              />
              <span
                onClick={togglePasswordVisibility}
                className="input-icon clickable"
                style={{ cursor: isRegistering ? 'not-allowed' : 'pointer' }}
              >
                {showPassword ? <FaEyeSlash /> : <FaEye />}
              </span>
            </div>

            <div className="input-wrapper">
              <input
                type={showConfirmPassword ? "text" : "password"}
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                disabled={isRegistering}
                minLength={6}
              />
              <span
                onClick={toggleConfirmPasswordVisibility}
                className="input-icon clickable"
                style={{ cursor: isRegistering ? 'not-allowed' : 'pointer' }}
              >
                {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
              </span>
            </div>

            <button 
              type="submit" 
              disabled={isRegistering}
              className={isRegistering ? 'button-disabled' : ''}
            >
              {isRegistering ? (
                <>
                  <FaSpinner className="animate-spin" />
                  Creating Account...
                </>
              ) : (
                'Create Account'
              )}
            </button>
          </form>

          {message && (
            <div className={`message ${message.includes('❌') ? 'error' : ''}`}>
              {message}
            </div>
          )}
        </div>

        <div className="auth-footer">
          <div className="auth-options">
            <p>
              Already have an account?{" "}
              <Link to="/login" className="login-link">
                Sign In
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Register;