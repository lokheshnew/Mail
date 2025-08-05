import React, { useState, useEffect } from "react";

const ScheduleModal = ({ onClose, onSchedule }) => {
  const [scheduleDate, setScheduleDate] = useState("");
  const [scheduleTime, setScheduleTime] = useState("");
  const [minDate, setMinDate] = useState("");
  const [minTime, setMinTime] = useState("");

  useEffect(() => {
    // Set minimum date to today
    const today = new Date();
    const todayString = today.toISOString().split('T')[0];
    setMinDate(todayString);
    
    // If selected date is today, set minimum time to current time
    if (scheduleDate === todayString) {
      const now = new Date();
      const currentTime = now.toTimeString().slice(0, 5);
      setMinTime(currentTime);
    } else {
      setMinTime("");
    }
  }, [scheduleDate]);

  const handleSchedule = () => {
    if (!scheduleDate) {
      alert("Please select a date");
      return;
    }
    
    if (!scheduleTime) {
      alert("Please select a time");
      return;
    }

    const scheduledDateTime = new Date(`${scheduleDate}T${scheduleTime}`);
    const now = new Date();

    // Check if scheduled time is in the future
    if (scheduledDateTime <= now) {
      alert("Scheduled time must be in the future");
      return;
    }

    onSchedule(scheduleDate, scheduleTime);
  };

  const handleDateChange = (e) => {
    const selectedDate = e.target.value;
    setScheduleDate(selectedDate);
    
    // If selected date is today, ensure time is in the future
    const today = new Date().toISOString().split('T')[0];
    if (selectedDate === today) {
      const now = new Date();
      const currentTime = now.toTimeString().slice(0, 5);
      setMinTime(currentTime);
      
      // If current time is greater than selected time, clear the time
      if (scheduleTime && scheduleTime <= currentTime) {
        setScheduleTime("");
      }
    } else {
      setMinTime("");
    }
  };

  return (
    <div className="schedule-overlay">
      <div className="schedule-modal-card animate-scaleIn">
        <h4>📅 Schedule Email</h4>

        <div className="schedule-fields">
          <div className="date-picker">
            <label>Date *</label>
            <input
              className="input"
              type="date"
              value={scheduleDate}
              onChange={handleDateChange}
              min={minDate}
              required
            />
          </div>
          <div className="time-picker">
            <label>Time *</label>
            <input
              className="input"
              type="time"
              value={scheduleTime}
              onChange={(e) => setScheduleTime(e.target.value)}
              min={minTime}
              required
            />
          </div>
        </div>

        {scheduleDate && scheduleTime && (
          <div className="alert alert-info" style={{ marginTop: "var(--space-4)" }}>
            <strong>Scheduled for:</strong> {new Date(`${scheduleDate}T${scheduleTime}`).toLocaleString()}
          </div>
        )}

        <div className="schedule-actions">
          <button onClick={onClose} className="cancel-btn">
            Cancel
          </button>
          <button 
            onClick={handleSchedule} 
            className="confirm-btn"
            disabled={!scheduleDate || !scheduleTime}
          >
            📅 Schedule Email
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScheduleModal;