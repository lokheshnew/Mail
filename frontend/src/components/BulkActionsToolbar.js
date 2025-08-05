import React from "react";
import { FaTrash, FaEnvelopeOpen, FaEnvelope, FaUndo } from "react-icons/fa";

const BulkActionsToolbar = ({ selectedCount, onBulkAction, onClearSelection, activeTab }) => {
  return (
    <div className="bulk-actions-toolbar">
      <span>📋 {selectedCount} email{selectedCount !== 1 ? 's' : ''} selected</span>
      
      {activeTab === "trash" ? (
        <button onClick={() => onBulkAction("restore")} className="flex items-center gap-2">
          <FaUndo /> Restore
        </button>
      ) : (
        <button onClick={() => onBulkAction("delete")} className="flex items-center gap-2">
          <FaTrash /> Delete
        </button>
      )}
      
      {activeTab !== "trash" && (
        <>
          <button onClick={() => onBulkAction("mark_read")} className="flex items-center gap-2">
            <FaEnvelopeOpen /> Mark Read
          </button>
          <button onClick={() => onBulkAction("mark_unread")} className="flex items-center gap-2">
            <FaEnvelope /> Mark Unread
          </button>
        </>
      )}
      
      <button onClick={onClearSelection} className="flex items-center gap-2">
        ✕ Cancel
      </button>
    </div>
  );
};

export default BulkActionsToolbar;