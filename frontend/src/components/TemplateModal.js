import React, { useState } from "react";
import { API_BASE_URL } from "../config";
import { toast } from "react-toastify";
import "./templateModal.css";

const TemplateModal = ({ onClose, onSaved, token }) => {
  const [templateName, setTemplateName] = useState("");
  const [templateSubject, setTemplateSubject] = useState("");
  const [templateBody, setTemplateBody] = useState("");
  const [isSaving, setIsSaving] = useState(false);

  const handleSaveTemplate = async () => {
    if (!templateName.trim()) {
      toast.error("Please enter a template name");
      return;
    }

    if (!templateSubject.trim() && !templateBody.trim()) {
      toast.error("Please enter either a subject or body for the template");
      return;
    }

    setIsSaving(true);

    try {
      // ✅ CORRECT ENDPOINT - Using /template/save_template
      const res = await fetch(`${API_BASE_URL}/template/save_template`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: templateName.trim(),
          subject: templateSubject.trim(),
          body: templateBody.trim(),
        }),
      });

      const data = await res.json();

      if (res.ok) {
        toast.success("Template saved successfully!");
        onSaved();
      } else {
        toast.error(data.error || "Failed to save template");
      }
    } catch (err) {
      console.error("Error saving template:", err);
      toast.error("Error saving template");
    } finally {
      setIsSaving(false);
    }
  };

  const handleCancel = () => {
    if (templateName.trim() || templateSubject.trim() || templateBody.trim()) {
      if (window.confirm("Are you sure you want to discard this template?")) {
        resetForm();
        onClose();
      }
    } else {
      onClose();
    }
  };

  const resetForm = () => {
    setTemplateName("");
    setTemplateSubject("");
    setTemplateBody("");
  };

  return (
    <div className="modal-overlay">
      <div className="modal animate-scaleIn">
        <div className="modal-header">
          <h3 className="modal-title">Create New Template</h3>
          <button className="modal-close" onClick={handleCancel}>
            ✕
          </button>
        </div>

        <div className="modal-body">
          <div className="input-group">
            <label className="input-label">Template Name *</label>
            <input
              className="input"
              type="text"
              placeholder="Enter template name"
              value={templateName}
              onChange={(e) => setTemplateName(e.target.value)}
              required
              maxLength={100}
              disabled={isSaving}
            />
          </div>

          <div className="input-group">
            <label className="input-label">Subject</label>
            <input
              className="input"
              type="text"
              placeholder="Email subject"
              value={templateSubject}
              onChange={(e) => setTemplateSubject(e.target.value)}
              maxLength={200}
              disabled={isSaving}
            />
          </div>

          <div className="input-group">
            <label className="input-label">Template Body</label>
            <textarea
              className="textarea"
              placeholder="Enter your template content here..."
              value={templateBody}
              onChange={(e) => setTemplateBody(e.target.value)}
              rows="8"
              maxLength={5000}
              disabled={isSaving}
              style={{ minHeight: "150px" }}
            />
          </div>
        </div>

        <div className="modal-footer">
          <button
            className="btn btn-ghost"
            onClick={handleCancel}
            disabled={isSaving}
          >
            Cancel
          </button>
          <button
            className="btn btn-primary"
            onClick={handleSaveTemplate}
            disabled={!templateName.trim() || isSaving}
          >
            {isSaving ? (
              <>
                <span className="loading-spinner"></span>
                Saving...
              </>
            ) : (
              "💾 Save Template"
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default TemplateModal;
