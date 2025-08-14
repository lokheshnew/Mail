import React, { useState, useEffect } from "react";
import { API_BASE_URL } from "../config";
import { toast } from "react-toastify";
import RecipientInput from "./RecipientInput";
import ScheduleModal from "./ScheduleModal";
import "./composeModal.css";

const ComposeModal = ({
  onClose,
  onSent,
  onDraftSaved,
  onScheduled,
  templates,
  editingDraft,
  token,
  isDarkMode,
}) => {
  const [recipient, setRecipient] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [attachment, setAttachment] = useState("");
  const [file, setFile] = useState(null);
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [isSavingDraft, setIsSavingDraft] = useState(false);

  // Load draft data if editing
  useEffect(() => {
    if (editingDraft) {
      setRecipient(editingDraft.to || "");
      setSubject(editingDraft.subject || "");
      setBody(editingDraft.body || "");
      setAttachment(editingDraft.attachment || "");
    }
  }, [editingDraft]);

  const resetForm = () => {
    setRecipient("");
    setSubject("");
    setBody("");
    setAttachment("");
    setFile(null);
  };

  const handleFileUpload = async () => {
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`${API_BASE_URL}/file/upload`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });
      const data = await res.json();
      if (data.url) {
        setAttachment(data.url);
        toast.success("File uploaded successfully!");
        setFile(null); // Clear file after successful upload
      } else {
        toast.error("Failed to upload file");
      }
    } catch (err) {
      console.error("File upload error:", err);
      toast.error("Error uploading file");
    }
  };

  const handleSend = async () => {
    if (!recipient.trim()) {
      toast.error("Please enter a recipient");
      return;
    }

    if (!subject.trim() && !body.trim()) {
      toast.error("Please enter a subject or message");
      return;
    }

    setIsSending(true);

    try {
      const res = await fetch(`${API_BASE_URL}/mail/send`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          to: recipient.trim(),
          subject: subject.trim(),
          body: body.trim(),
          attachment,
        }),
      });

      const data = await res.json();
      if (data.message) {
        toast.success("Email sent successfully!");

        // If editing draft, delete it after sending
        if (editingDraft) {
          await handleDeleteDraft(editingDraft);
        }

        onSent();
        onClose();
        resetForm();
      } else {
        toast.error(data.error || "Failed to send email.");
      }
    } catch (err) {
      console.error("Send error:", err);
      toast.error("An error occurred while sending the email.");
    } finally {
      setIsSending(false);
    }
  };

  const handleSaveDraft = async () => {
    if (!recipient.trim() && !subject.trim() && !body.trim()) {
      toast.error("Please enter some content to save as draft");
      return;
    }

    setIsSavingDraft(true);

    try {
      const res = await fetch(`${API_BASE_URL}/mail/save_draft`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          to: recipient.trim(),
          subject: subject.trim(),
          body: body.trim(),
          attachment,
        }),
      });

      if (res.ok) {
        toast.success("Draft saved successfully!");
        onDraftSaved();
        onClose();
        resetForm();
      } else {
        const errorData = await res.json();
        toast.error(errorData.error || "Failed to save draft");
      }
    } catch (err) {
      console.error("Error saving draft:", err);
      toast.error("Error saving draft");
    } finally {
      setIsSavingDraft(false);
    }
  };

  const handleDeleteDraft = async (draft) => {
    try {
      const res = await fetch(`${API_BASE_URL}/mail/delete_draft`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ draft }),
      });
      return res.ok;
    } catch (err) {
      console.error("Error deleting draft:", err);
      return false;
    }
  };

  const handleUseTemplate = (template) => {
    if (template) {
      setSubject(template.subject || "");
      setBody(template.body || "");
      toast.success(`Template "${template.name}" applied`);
    }
  };

  const handleScheduleEmail = async (scheduleDate, scheduleTime) => {
    if (!scheduleDate || !scheduleTime) {
      toast.error("Please select both date and time.");
      return;
    }

    if (!recipient.trim()) {
      toast.error("Please enter a recipient");
      return;
    }

    const scheduledDateTime = new Date(`${scheduleDate}T${scheduleTime}`);

    // Check if scheduled time is in the future
    if (scheduledDateTime <= new Date()) {
      toast.error("Scheduled time must be in the future");
      return;
    }

    try {
      const res = await fetch(`${API_BASE_URL}/mail/schedule`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          to: recipient.trim(),
          subject: subject.trim(),
          body: body.trim(),
          attachment,
          scheduleTime: scheduledDateTime.toISOString(),
        }),
      });

      const data = await res.json();
      if (data.message) {
        toast.success("Email scheduled successfully!");
        setShowScheduleModal(false);
        onScheduled();
        onClose();
        resetForm();
      } else {
        toast.error(data.error || "Failed to schedule email.");
      }
    } catch (err) {
      console.error("Schedule error:", err);
      toast.error("An error occurred while scheduling the email.");
    }
  };

  const handleClose = () => {
    if (recipient.trim() || subject.trim() || body.trim()) {
      if (window.confirm("Are you sure you want to discard this email?")) {
        resetForm();
        onClose();
      }
    } else {
      onClose();
    }
  };

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      // Check file size (limit to 10MB)
      if (selectedFile.size > 10 * 1024 * 1024) {
        toast.error("File size must be less than 10MB");
        return;
      }
      setFile(selectedFile);
    }
  };

  return (
    <div className={`compose-overlay ${isDarkMode ? "dark" : ""}`}>
      <div
        className={`compose-modal animate-scaleIn ${isDarkMode ? "dark" : ""}`}
      >
        <div className={`compose-header ${isDarkMode ? "dark" : ""}`}>
          <h3>{editingDraft ? "Edit Draft" : "New Message"}</h3>
          <button className="close-btn" onClick={handleClose}>
            ✕
          </button>
        </div>

        <div className="compose-form">
          <RecipientInput
            recipient={recipient}
            onRecipientChange={setRecipient}
            token={token}
          />

          <div className="form-row">
            <label>Subject</label>
            <input
              type="text"
              placeholder="Subject"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              maxLength={200}
            />
          </div>

          <div className="form-row message-row">
            <label>Message</label>
            <textarea
              placeholder="Compose your message..."
              value={body}
              onChange={(e) => setBody(e.target.value)}
              maxLength={5000}
            />
          </div>

          <div className="attachment-section">
            <input
              type="file"
              id="file-input"
              style={{ display: "none" }}
              onChange={handleFileChange}
              accept=".pdf,.doc,.docx,.txt,.jpg,.jpeg,.png,.gif"
            />
            <label htmlFor="file-input" className="attach-btn">
              📎 Attach files
            </label>

            {file && (
              <div className="file-selected">
                <span>
                  {file.name} ({Math.round(file.size / 1024)} KB)
                </span>
                <button onClick={handleFileUpload} className="upload-btn">
                  Upload
                </button>
                <button
                  onClick={() => setFile(null)}
                  className="upload-btn"
                  style={{ marginLeft: "8px" }}
                >
                  Remove
                </button>
              </div>
            )}

            {attachment && (
              <div className="attachment-preview">
                <span className="attachment-icon">📎</span>
                <a href={attachment} target="_blank" rel="noopener noreferrer">
                  {attachment.split("/").pop()}
                </a>
                <button onClick={() => setAttachment("")}>✕</button>
              </div>
            )}
          </div>

          <div className="compose-actions">
            {templates && templates.length > 0 && (
              <div className="template-selection">
                <label>Use Template:</label>
                <select
                  onChange={(e) => {
                    const template = templates.find(
                      (t) => t.name === e.target.value
                    );
                    if (template) {
                      handleUseTemplate(template);
                      e.target.value = ""; // Reset select
                    }
                  }}
                  defaultValue=""
                >
                  <option value="">Select a template...</option>
                  {templates.map((template, index) => (
                    <option key={index} value={template.name}>
                      {template.name}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <button
              className="btn primary"
              onClick={handleSend}
              disabled={!recipient.trim() || isSending}
            >
              {isSending ? "Sending..." : "Send"}
            </button>

            <button
              className="btn secondary"
              onClick={() => setShowScheduleModal(true)}
              disabled={!recipient.trim() || isSending}
            >
              Schedule & Send
            </button>

            <button
              className="btn outline"
              onClick={handleSaveDraft}
              disabled={isSavingDraft}
            >
              {isSavingDraft ? "Saving..." : "Save Draft"}
            </button>

            <button className="btn muted" onClick={handleClose}>
              Discard
            </button>
          </div>
        </div>
      </div>

      {showScheduleModal && (
        <ScheduleModal
          onClose={() => setShowScheduleModal(false)}
          onSchedule={handleScheduleEmail}
        />
      )}
    </div>
  );
};

export default ComposeModal;
