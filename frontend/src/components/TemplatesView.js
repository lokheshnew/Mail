import React from "react";
import "./templatesView.css";

const TemplatesView = ({
  templates,
  onCreateTemplate,
  onUseTemplate,
  isDarkMode,
}) => {
  return (
    <div className="templates-view">
      <div className={`templates-header ${isDarkMode ? "dark" : ""}`}>
        <h2>📝 Email Templates</h2>
        <button onClick={onCreateTemplate} className="btn btn-primary">
          ➕ Create Template
        </button>
      </div>

      {templates.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📝</div>
          <h3>No Templates Yet</h3>
          <p>
            Create your first email template to save time when composing emails
          </p>
          <button
            onClick={onCreateTemplate}
            className="btn btn-primary"
            style={{ marginTop: "var(--space-4)" }}
          >
            Create Your First Template
          </button>
        </div>
      ) : (
        <div className="templates-grid">
          {templates.map((template, index) => (
            <div
              key={index}
              className="template-card animate-fadeIn"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <h3>{template.name}</h3>
              <p>
                <strong>Subject:</strong> {template.subject || "No subject"}
              </p>
              <p className="template-preview">
                {template.body
                  ? template.body.length > 100
                    ? template.body.substring(0, 100) + "..."
                    : template.body
                  : "No content"}
              </p>
              <div className="template-actions">
                <button
                  onClick={() => onUseTemplate(template)}
                  className="btn btn-primary btn-sm"
                >
                  ✉️ Use Template
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default TemplatesView;
