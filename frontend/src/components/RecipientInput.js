import React, { useState, useEffect } from "react";
import { API_BASE_URL } from "../config";

const RecipientInput = ({ recipient, onRecipientChange, token }) => {
  const [suggestions, setSuggestions] = useState([]);
  const [knownRecipients, setKnownRecipients] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const fetchRecipients = async () => {
    if (!token) return;
    
    setIsLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/mail/recipients`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      const data = await res.json();
      setKnownRecipients(data.recipients || []);
    } catch (err) {
      console.error("Error fetching recipients", err);
      setKnownRecipients([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (token) {
      fetchRecipients();
    }
  }, [token]);

  const handleFocus = () => {
    if (knownRecipients.length === 0 && token) {
      fetchRecipients();
    }
    setShowSuggestions(true);
  };

  const handleInputChange = (e) => {
    const input = e.target.value;
    onRecipientChange(input);

    if (input.trim() && knownRecipients.length > 0) {
      const filtered = knownRecipients.filter((email) =>
        email.toLowerCase().includes(input.toLowerCase())
      );
      setSuggestions(filtered.slice(0, 5)); // Limit to 5 suggestions
    } else {
      setSuggestions([]);
    }
  };

  const handleSuggestionClick = (email) => {
    onRecipientChange(email);
    setSuggestions([]);
    setShowSuggestions(false);
  };

  const handleBlur = () => {
    // Delay hiding suggestions to allow for clicks
    setTimeout(() => {
      setShowSuggestions(false);
      setSuggestions([]);
    }, 200);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Escape') {
      setShowSuggestions(false);
      setSuggestions([]);
    }
  };

  return (
    <div className="form-row">
      <label>To</label>
      <div style={{ position: "relative", flex: 1 }}>
        <input
          type="email"
          placeholder="Enter recipient email address"
          value={recipient}
          onFocus={handleFocus}
          onChange={handleInputChange}
          onBlur={handleBlur}
          onKeyDown={handleKeyDown}
          required
          maxLength={100}
        />
        
        {showSuggestions && suggestions.length > 0 && (
          <ul className="suggestions-dropdown animate-slideDown">
            {suggestions.map((email, idx) => (
              <li
                key={idx}
                onClick={() => handleSuggestionClick(email)}
                onMouseDown={(e) => e.preventDefault()} // Prevent blur when clicking
              >
                📧 {email}
              </li>
            ))}
          </ul>
        )}
        
        {showSuggestions && isLoading && (
          <div className="suggestions-dropdown animate-slideDown">
            <li style={{ color: '#9aa0a6', fontStyle: 'italic' }}>
              <span className="loading-spinner"></span> Loading recipients...
            </li>
          </div>
        )}
      </div>
    </div>
  );
};

export default RecipientInput;