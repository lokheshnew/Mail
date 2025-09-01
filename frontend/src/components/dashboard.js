import React, { useEffect, useState } from "react";
import "./dashboard.css";
import { API_BASE_URL } from "../config";
import { toast } from "react-toastify";

// Import all components
import Header from "./Header";
import Sidebar from "./Sidebar";
import EmailList from "./EmailList";
import StorageView from "./StorageView";
import TemplatesView from "./TemplatesView";
import ComposeModal from "./ComposeModal";
import TemplateModal from "./TemplateModal";
import ConfirmModal from "./ConfirmModal";

const Dashboard = () => {
  // All state variables
  const [activeTab, setActiveTab] = useState("inbox");
  const [inbox, setInbox] = useState([]);
  const [sent, setSent] = useState([]);
  const [drafts, setDrafts] = useState([]);
  const [trash, setTrash] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [searchResults, setSearchResults] = useState([]);
  const [storageInfo, setStorageInfo] = useState(null);
  const [emailStats, setEmailStats] = useState(null);
  const [showCompose, setShowCompose] = useState(false);
  const [showTemplateModal, setShowTemplateModal] = useState(false);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [selectedEmails, setSelectedEmails] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [scheduled, setScheduled] = useState([]);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [confirmMessage, setConfirmMessage] = useState("");
  const [onConfirm, setOnConfirm] = useState(null);
  const [editingDraft, setEditingDraft] = useState(null);
  const [isDarkMode, setIsDarkMode] = useState(false);

  const username = localStorage.getItem("username");
  const email = localStorage.getItem("email");
  const token = localStorage.getItem("token");

  // Fetch functions
  const fetchInbox = async () => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/inbox
      const res = await fetch(`${API_BASE_URL}/mail/inbox/${email}`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      const data = await res.json();
      if (data.inbox) {
        const filteredInbox = data.inbox.filter(
          (mail) => mail.message_status !== "deleted"
        );
        setInbox(filteredInbox);
      }
    } catch (err) {
      console.error("Error fetching inbox:", err);
      toast.error("Failed to load inbox");
    }
  };

  const fetchSent = async () => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/sent
      const res = await fetch(`${API_BASE_URL}/mail/sent/${email}`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      const data = await res.json();
      if (data.sent) {
        const filteredSent = data.sent.filter(
          (mail) => mail.message_status !== "deleted"
        );
        setSent(filteredSent);
      }
    } catch (err) {
      console.error("Error fetching sent:", err);
      toast.error("Failed to load sent emails");
    }
  };

  const fetchDrafts = async () => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/drafts
      const res = await fetch(`${API_BASE_URL}/mail/drafts/${email}`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      const data = await res.json();
      if (data.drafts) {
        setDrafts(data.drafts);
      }
    } catch (err) {
      console.error("Error fetching drafts:", err);
      toast.error("Failed to load drafts");
    }
  };

  const fetchTrash = async () => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/trash
      const res = await fetch(`${API_BASE_URL}/mail/trash/${email}`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      const data = await res.json();
      if (data.trash) {
        setTrash(data.trash);
      }
    } catch (error) {
      console.error("Failed to fetch trash emails:", error);
      toast.error("Failed to load trash");
    }
  };

  const fetchTemplates = async () => {
    try {
      // ✅ CORRECT ENDPOINT - Using /template/templates
      const res = await fetch(`${API_BASE_URL}/template/templates/${email}`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      const data = await res.json();
      if (data.templates) {
        setTemplates(data.templates);
      }
    } catch (err) {
      console.error("Error fetching templates:", err);
      toast.error("Failed to load templates");
    }
  };

  const fetchStorage = async () => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/storage
      const res = await fetch(`${API_BASE_URL}/mail/storage/${email}`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      const data = await res.json();
      setStorageInfo(data);
    } catch (err) {
      console.error("Error fetching storage:", err);
      toast.error("Failed to load storage info");
    }
  };

  const fetchEmailStats = async () => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/stats
      const res = await fetch(`${API_BASE_URL}/mail/stats/${email}`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      const data = await res.json();
      setEmailStats(data);
    } catch (err) {
      console.error("Error fetching email stats:", err);
      toast.error("Failed to load email stats");
    }
  };

  const fetchScheduled = async () => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/scheduled
      const res = await fetch(`${API_BASE_URL}/mail/scheduled`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({}),
      });

      const data = await res.json();

      if (Array.isArray(data.scheduled)) {
        const filteredScheduled = data.scheduled.filter(
          (mail) => mail.message_status !== "deleted"
        );
        setScheduled(filteredScheduled);
      } else {
        console.error("Unexpected response:", data);
        toast.error("Failed to load scheduled emails.");
      }
    } catch (err) {
      console.error("Error fetching scheduled emails:", err);
      toast.error("An error occurred while fetching scheduled emails.");
    }
  };

  // Search functionality
  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      setSearchResults([]);
      setIsSearching(false);
      return;
    }

    setIsSearching(true);
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/search
      const res = await fetch(`${API_BASE_URL}/mail/search`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          query: searchQuery,
          folder: activeTab === "sent" ? "sent" : "inbox",
        }),
      });
      const data = await res.json();
      if (data.results) {
        setSearchResults(data.results);
      }
    } catch (err) {
      console.error("Search error:", err);
      toast.error("Search failed");
    } finally {
      setIsSearching(false);
    }
  };

  // Get current emails based on active tab
  const getCurrentEmails = () => {
    if (searchQuery.trim() && searchResults.length > 0) {
      return searchResults;
    }

    switch (activeTab) {
      case "inbox":
        return inbox;
      case "sent":
        return sent;
      case "trash":
        return trash;
      case "drafts":
        return drafts;
      case "scheduled":
        return scheduled;
      default:
        return [];
    }
  };

  const refreshCurrentFolder = () => {
    switch (activeTab) {
      case "inbox":
        fetchInbox();
        break;
      case "sent":
        fetchSent();
        break;
      case "drafts":
        fetchDrafts();
        break;
      case "scheduled":
        fetchScheduled();
        break;
      case "trash":
        fetchTrash();
        break;
      default:
        break;
    }
  };

  const handleLogout = () => {
    // ✅ CORRECT ENDPOINT - Using /auth/logout
    fetch(`${API_BASE_URL}/auth/logout`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    })
      .then(() => {
        localStorage.clear();
        window.location.href = "/";
      })
      .catch(() => {
        // Even if logout fails, clear local storage and redirect
        localStorage.clear();
        window.location.href = "/";
      });
  };

  const handleClearSearch = () => {
    setSearchQuery("");
    setSearchResults([]);
    setIsSearching(false);
  };

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setSelectedEmail(null);
    handleClearSearch();

    switch (tab) {
      case "inbox":
        fetchInbox();
        break;
      case "sent":
        fetchSent();
        break;
      case "drafts":
        fetchDrafts();
        break;
      case "templates":
        fetchTemplates();
        break;
      case "scheduled":
        fetchScheduled();
        break;
      case "trash":
        fetchTrash();
        break;
      case "storage":
        fetchStorage();
        fetchEmailStats();
        break;
      default:
        break;
    }
  };

  // Initial data fetch
  useEffect(() => {
    // Check if user is authenticated
    if (!token || !email) {
      localStorage.clear();
      window.location.href = "/login";
      return;
    }

    fetchInbox();
    fetchSent();
    fetchDrafts();
    fetchEmailStats();
  }, [token, email]);

  // Search effect
  useEffect(() => {
    const searchTimeout = setTimeout(() => {
      if (searchQuery.trim()) {
        handleSearch();
      } else {
        setSearchResults([]);
        setIsSearching(false);
      }
    }, 500); // Debounce search

    return () => clearTimeout(searchTimeout);
  }, [searchQuery, activeTab]);

  const renderMainContent = () => {
    switch (activeTab) {
      case "storage":
        return (
          <StorageView
            storageInfo={storageInfo}
            emailStats={emailStats}
            isDarkMode={isDarkMode}
            toggleDarkMode={toggleDarkMode}
          />
        );
      case "templates":
        return (
          <TemplatesView
            templates={templates}
            onCreateTemplate={() => setShowTemplateModal(true)}
            onUseTemplate={(template) => {
              // This would be passed to compose modal
              setShowCompose(true);
            }}
            isDarkMode={isDarkMode}
            toggleDarkMode={toggleDarkMode}
          />
        );
      default:
        return (
          <EmailList
            emails={searchQuery.trim() ? searchResults : getCurrentEmails()}
            activeTab={activeTab}
            selectedEmail={selectedEmail}
            selectedEmails={selectedEmails}
            searchQuery={searchQuery}
            isSearching={isSearching}
            onSelectEmail={setSelectedEmail}
            onSelectEmails={setSelectedEmails}
            onRefresh={refreshCurrentFolder}
            onEditDraft={setEditingDraft}
            onShowCompose={setShowCompose}
            onShowConfirm={(message, callback) => {
              setConfirmMessage(message);
              setOnConfirm(() => callback);
              setShowConfirmModal(true);
            }}
            token={token}
            fetchTrash={fetchTrash}
            fetchInbox={fetchInbox}
            fetchSent={fetchSent}
            isDarkMode={isDarkMode}
            toggleDarkMode={toggleDarkMode}
          />
        );
    }
  };

  const toggleDarkMode = () => {
    setIsDarkMode((prev) => !prev);
  };

  return (
    <div className={`gmail-dashboard ${isDarkMode ? "dark" : ""}`}>
      <Header
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        onClearSearch={handleClearSearch}
        username={username}
        onLogout={handleLogout}
        isDarkMode={isDarkMode}
        toggleDarkMode={toggleDarkMode}
      />

      <div className="gmail-body">
        <Sidebar
          activeTab={activeTab}
          onTabChange={handleTabChange}
          onCompose={() => setShowCompose(true)}
          counts={{
            inbox: inbox.length,
            sent: sent.length,
            drafts: drafts.length,
            templates: templates.length,
            scheduled: scheduled.length,
            trash: trash.length,
          }}
          isDarkMode={isDarkMode}
        />

        <main className="gmail-main">{renderMainContent()}</main>

        {showCompose && (
          <ComposeModal
            onClose={() => {
              setShowCompose(false);
              setEditingDraft(null);
            }}
            onSent={() => {
              fetchSent();
              refreshCurrentFolder();
            }}
            onDraftSaved={() => {
              fetchDrafts();
            }}
            onScheduled={() => {
              fetchScheduled();
            }}
            templates={templates}
            editingDraft={editingDraft}
            token={token}
            isDarkMode={isDarkMode}
            toggleDarkMode={toggleDarkMode}
          />
        )}

        {showTemplateModal && (
          <TemplateModal
            onClose={() => setShowTemplateModal(false)}
            onSaved={() => {
              fetchTemplates();
              setShowTemplateModal(false);
            }}
            token={token}
            isDarkMode={isDarkMode}
            toggleDarkMode={toggleDarkMode}
          />
        )}
      </div>

      {showConfirmModal && (
        <ConfirmModal
          message={confirmMessage}
          onConfirm={() => {
            if (onConfirm) onConfirm();
            setShowConfirmModal(false);
          }}
          onCancel={() => setShowConfirmModal(false)}
          isDarkMode={isDarkMode}
          toggleDarkMode={toggleDarkMode}
        />
      )}
    </div>
  );
};

export default Dashboard;
