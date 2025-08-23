import React from "react";
import { FaSun, FaMoon } from "react-icons/fa";
import "./themeToggle.css";

const ThemeToggle = ({ isDarkMode, toggleDarkMode }) => {
  return (
    <div className="theme-toggle" onClick={toggleDarkMode} title="Toggle Theme">
      <div className={`icon-wrapper ${isDarkMode ? "dark" : "light"}`}>
        {isDarkMode ? <FaMoon /> : <FaSun />}
      </div>
    </div>
  );
};

export default ThemeToggle;
