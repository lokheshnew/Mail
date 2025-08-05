import React from "react";
import { FaSearch } from "react-icons/fa";
import ThemeToggle from "./ThemeToggle";

const Header = ({ searchQuery, onSearchChange, username, onLogout, onClearSearch }) => {
  const getInitials = (name) => {
    return name ? name.charAt(0).toUpperCase() : "U";
  };

  const handleSearchClear = () => {
    if (onClearSearch) {
      onClearSearch();
    }
  };

  return (
    <header className="gmail-header">
      <div className="header-left">
        <div className="gmail-logo">
          <div className="auth-logo">
            📧
          </div>
          <span className="logo-text">MailApp</span>
        </div>
        <div className="search-container">
          <FaSearch className="search-icon" />
          <input
            type="text"
            placeholder="Search mail"
            className="search-input"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
          />
          {searchQuery && (
            <button 
              className="search-clear"
              onClick={handleSearchClear}
              title="Clear search"
            >
              ✕
            </button>
          )}
        </div>
      </div>
      <div className="header-right">
        <ThemeToggle />
        <div className="user-info">
          <div className="user-avatar">{getInitials(username)}</div>
          <span className="username">{username}</span>
        </div>
        <button className="logout-btn" onClick={onLogout}>
          Sign out
        </button>
      </div>
    </header>
  );
};

export default Header;