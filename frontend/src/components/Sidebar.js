import React from "react";
import {
  FaInbox,
  FaPaperPlane,
  FaFileAlt,
  FaClone,
  FaClock,
  FaTrash,
  FaDatabase,
  FaPenNib,
} from "react-icons/fa";
import "./sidebar.css";

const Sidebar = ({ activeTab, onTabChange, onCompose, counts, isDarkMode }) => {
  const navItems = [
    { id: "inbox", icon: FaInbox, text: "Inbox", count: counts.inbox },
    { id: "sent", icon: FaPaperPlane, text: "Sent", count: counts.sent },
    { id: "drafts", icon: FaFileAlt, text: "Drafts", count: counts.drafts },
    {
      id: "templates",
      icon: FaClone,
      text: "Templates",
      count: counts.templates,
    },
    {
      id: "scheduled",
      icon: FaClock,
      text: "Scheduled",
      count: counts.scheduled,
    },
    { id: "trash", icon: FaTrash, text: "Trash", count: counts.trash },
    { id: "storage", icon: FaDatabase, text: "Storage", count: null },
  ];

  return (
    <aside className={`gmail-sidebar ${isDarkMode ? "dark" : ""}`}>
      <button className="compose-button" onClick={onCompose}>
        <FaPenNib className="compose-icon" />
        Compose
      </button>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const IconComponent = item.icon;
          return (
            <div
              key={item.id}
              className={`nav-item ${activeTab === item.id ? "active" : ""}`}
              onClick={() => onTabChange(item.id)}
            >
              <span className="nav-icon">
                <IconComponent />
              </span>
              <span className="nav-text">{item.text}</span>
              {item.count !== null && item.count > 0 && (
                <span className="nav-count">{item.count}</span>
              )}
            </div>
          );
        })}
      </nav>
    </aside>
  );
};

export default Sidebar;
