import React from "react";

const ConfirmModal = ({ message, onConfirm, onCancel }) => {
  return (
    <div className="modal-overlay">
      <div className="modal animate-scaleIn" style={{ maxWidth: "400px" }}>
        <div className="modal-header">
          <h3 className="modal-title">Confirm Action</h3>
        </div>
        
        <div className="modal-body">
          <p style={{ fontSize: "1rem", marginBottom: "var(--space-6)", color: "var(--text-primary)" }}>
            {message}
          </p>
        </div>
        
        <div className="modal-footer">
          <button
            onClick={onCancel}
            className="btn btn-ghost"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="btn btn-danger"
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmModal;