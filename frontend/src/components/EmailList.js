import React from "react";
import { API_BASE_URL } from "../config";
import { toast } from "react-toastify";
import EmailItem from "./EmailItem";
import BulkActionsToolbar from "./BulkActionsToolbar";

const EmailList = ({
  emails,
  activeTab,
  selectedEmail,
  selectedEmails,
  searchQuery,
  isSearching,
  onSelectEmail,
  onSelectEmails,
  onRefresh,
  onEditDraft,
  onShowCompose,
  onShowConfirm,
  token,
  fetchTrash,
  fetchInbox,
  fetchSent,
}) => {
  // Email actions
  const handleMarkAsRead = async (mail) => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/mark_read
      const res = await fetch(`${API_BASE_URL}/mail/mark_read`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ mail, activeTab }),
      });
      if (res.ok) {
        // Use a small delay to batch multiple updates if needed
        setTimeout(() => {
          onRefresh();
        }, 100);
      } else {
        const errorData = await res.json();
        toast.error(errorData.error || "Failed to mark as read");
      }
    } catch (err) {
      console.error("Error marking as read:", err);
      toast.error("Error marking as read");
    }
  };

  const handleMarkAsUnread = async (mail) => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/mark_unread
      const res = await fetch(`${API_BASE_URL}/mail/mark_unread`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ mail, activeTab }),
      });
      if (res.ok) {
        onRefresh();
      } else {
        const errorData = await res.json();
        toast.error(errorData.error || "Failed to mark as unread");
      }
    } catch (err) {
      console.error("Error marking as unread:", err);
      toast.error("Error marking as unread");
    }
  };

  const handleMoveToTrash = async (mailToDelete) => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/delete_mail
      const res = await fetch(`${API_BASE_URL}/mail/delete_mail`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ mail: mailToDelete, activeTab }),
      });
      const result = await res.json();

      if (result.message === "Deleted successfully") {
        onRefresh();
        fetchTrash();
        toast.success("Email moved to trash");
      } else {
        toast.error(result.error || "Failed to delete email");
      }
    } catch (err) {
      console.error("Error moving to trash:", err);
      toast.error("Error moving to trash");
    }
  };

  const handlePermanentDelete = (mail) => {
    onShowConfirm(
      "Are you sure you want to permanently delete this email?",
      async () => {
        try {
          // ✅ CORRECT ENDPOINT - Using /mail/permanent_delete
          const res = await fetch(`${API_BASE_URL}/mail/permanent_delete`, {
            method: "POST",
            headers: { 
              "Content-Type": "application/json",
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ mail }),
          });
          
          if (res.ok) {
            fetchTrash();
            toast.success("Email permanently deleted");
          } else {
            const errorData = await res.json();
            toast.error(errorData.error || "Failed to delete email permanently");
          }
        } catch (err) {
          console.error("Error permanently deleting:", err);
          toast.error("Error permanently deleting email");
        }
      }
    );
  };

  const handleRestoreEmail = async (mail) => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/restore_email
      const res = await fetch(`${API_BASE_URL}/mail/restore_email`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ mail }),
      });
      
      if (res.ok) {
        fetchTrash(); // Update trash count
        onRefresh(); // Update current folder
        
        // Update the folder where the email was restored to
        // Check if it's an inbox or sent email and refresh accordingly
        if (fetchInbox) fetchInbox(); // Refresh inbox
        if (fetchSent) fetchSent(); // Refresh sent
        toast.success("Email restored successfully");
      } else {
        const errorData = await res.json();
        toast.error(errorData.error || "Failed to restore email");
      }
    } catch (err) {
      console.error("Error restoring email:", err);
      toast.error("Error restoring email");
    }
  };

  const handleDeleteDraft = async (draft) => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/delete_draft
      const res = await fetch(`${API_BASE_URL}/mail/delete_draft`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ draft }),
      });
      
      if (res.ok) {
        onRefresh();
        toast.success("Draft deleted");
      } else {
        const errorData = await res.json();
        toast.error(errorData.error || "Failed to delete draft");
      }
    } catch (err) {
      console.error("Error deleting draft:", err);
      toast.error("Error deleting draft");
    }
  };

  const handleDeleteScheduled = async (mail) => {
    try {
      // ✅ CORRECT ENDPOINT - Using /mail/delete_mail
      const res = await fetch(`${API_BASE_URL}/mail/delete_mail`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          activeTab: "scheduled",
          mail: {
            from: mail.from,
            to: mail.to,
            subject: mail.subject,
            date_of_send: mail.date_of_send,
          },
        }),
      });

      const result = await res.json();

      if (result.message === "Deleted successfully") {
        onRefresh();
        toast.success("Scheduled email deleted");
      } else {
        toast.error(result.error || "Failed to delete scheduled email.");
      }
    } catch (err) {
      console.error(err);
      toast.error("An error occurred while deleting scheduled email.");
    }
  };

  const handleBulkAction = async (action) => {
    if (selectedEmails.length === 0) return;

    try {
      // ✅ CORRECT ENDPOINT - Using /mail/bulk_action
      const res = await fetch(`${API_BASE_URL}/mail/bulk_action`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          action,
          emails: selectedEmails,
          folder: activeTab,
        }),
      });
      
      if (res.ok) {
        onSelectEmails([]);
        onRefresh();
        
        // If bulk restoring from trash, refresh inbox and sent
        if (action === "restore" && activeTab === "trash") {
          if (fetchInbox) fetchInbox();
          if (fetchSent) fetchSent();
        }
        
        toast.success(`Bulk ${action} completed successfully`);
      } else {
        const errorData = await res.json();
        toast.error(errorData.error || `Failed to perform bulk ${action}`);
      }
    } catch (err) {
      console.error("Bulk action error:", err);
      toast.error(`Error performing bulk ${action}`);
    }
  };

  const handleEmailSelect = (mail, isChecked) => {
    const match = (m) =>
      m.subject === mail.subject &&
      m.to === mail.to &&
      m.from === mail.from &&
      (m.date_of_send === mail.date_of_send ||
        m.scheduled_date === mail.scheduled_date);

    if (isChecked) {
      onSelectEmails([...selectedEmails, mail]);
    } else {
      onSelectEmails(selectedEmails.filter((m) => !match(m)));
    }
  };

  const isEmailSelected = (mail) => {
    return selectedEmails.some(
      (m) =>
        m.subject === mail.subject &&
        m.to === mail.to &&
        m.from === mail.from &&
        (m.date_of_send === mail.date_of_send ||
          m.scheduled_date === mail.scheduled_date)
    );
  };

  const getEmptyStateConfig = () => {
    const configs = {
      sent: { icon: "📫", text: "No sent emails" },
      trash: { icon: "🗑️", text: "Trash is empty" },
      drafts: { icon: "📝", text: "No drafts" },
      scheduled: { icon: "📋", text: "No scheduled emails" },
      default: { icon: "📫", text: isSearching ? "No search results" : "Your inbox is empty" }
    };
    
    return configs[activeTab] || configs.default;
  };

  const emptyState = getEmptyStateConfig();

  return (
    <div className="email-list">
      {selectedEmails.length > 0 && (
        <BulkActionsToolbar
          selectedCount={selectedEmails.length}
          onBulkAction={handleBulkAction}
          onClearSelection={() => onSelectEmails([])}
          activeTab={activeTab}
        />
      )}

      {emails.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">{emptyState.icon}</div>
          <h3>{emptyState.text}</h3>
          {isSearching && <p>Try adjusting your search terms</p>}
        </div>
      ) : (
        emails.map((mail, index) => (
          <EmailItem
            key={`${mail.from}-${mail.to}-${mail.subject}-${index}`}
            mail={mail}
            index={index}
            activeTab={activeTab}
            isSelected={selectedEmail === index}
            isChecked={isEmailSelected(mail)}
            onSelect={() => onSelectEmail(selectedEmail === index ? null : index)}
            onCheck={(isChecked) => handleEmailSelect(mail, isChecked)}
            onMarkAsRead={() => handleMarkAsRead(mail)}
            onMarkAsUnread={() => handleMarkAsUnread(mail)}
            onMoveToTrash={() => handleMoveToTrash(mail)}
            onPermanentDelete={() => handlePermanentDelete(mail)}
            onRestore={() => handleRestoreEmail(mail)}
            onEditDraft={() => {
              onEditDraft(mail);
              onShowCompose(true);
            }}
            onDeleteDraft={() => handleDeleteDraft(mail)}
            onDeleteScheduled={() => handleDeleteScheduled(mail)}
          />
        ))
      )}
    </div>
  );
};

export default EmailList;