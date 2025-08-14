import React from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { CircularProgressbar, buildStyles } from "react-circular-progressbar";
import "react-circular-progressbar/dist/styles.css";
import "./storage.css";

// Soft and elegant colors that suit both dark and light themes
const COLORS = ["#4FC3F7", "#81C784", "#FFD54F", "#E57373", "#BA68C8"];

const StorageView = ({ storageInfo, emailStats, isDarkMode }) => {
  const chartData = [
    { name: "Received", value: emailStats?.total_received || 0 },
    { name: "Sent", value: emailStats?.total_sent || 0 },
    { name: "Unread", value: emailStats?.unread_count || 0 },
    { name: "Drafts", value: emailStats?.draft_count || 0 },
    { name: "Deleted", value: emailStats?.deleted_count || 0 },
  ];

  return (
    <div className={`storage-view ${isDarkMode ? "dark" : ""}`}>
      <div className="storage-card animate-fadeIn">
        <h2>Storage Usage</h2>
        {storageInfo && (
          <div className="circular-storage-container">
            <div className="circular-progress-wrapper">
              <CircularProgressbar
                value={storageInfo.percentage}
                text={`${storageInfo.percentage}%`}
                styles={buildStyles({
                  textSize: "16px",
                  pathColor:
                    storageInfo.status === "ok"
                      ? "#4CAF50"
                      : storageInfo.status === "warning"
                      ? "#FFC107"
                      : "#F44336",
                  textColor: "#38d8c8ff",
                  trailColor: "#e0e0e0",
                })}
              />
            </div>
            <div className="storage-details-enhanced">
              <div className="storage-label">
                <strong>Used:</strong> {storageInfo.used_mb} MB
              </div>
              <div
                className={`status-tag ${
                  storageInfo.status === "ok"
                    ? "ok"
                    : storageInfo.status === "warning"
                    ? "warning"
                    : "error"
                }`}
              >
                {storageInfo.status.toUpperCase()}
              </div>
            </div>
          </div>
        )}
      </div>

      {emailStats && (
        <div
          className="stats-card animate-fadeIn"
          style={{ animationDelay: "0.2s" }}
        >
          <h2>Email Statistics</h2>
          <ResponsiveContainer width="100%" height={400}>
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) =>
                  percent > 0.01
                    ? `${name}: ${(percent * 100).toFixed(0)}%`
                    : ""
                }
                outerRadius={120}
                fill="#8884d8"
                dataKey="value"
              >
                {chartData.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={COLORS[index % COLORS.length]}
                  />
                ))}
              </Pie>
              <Tooltip />
              <Legend verticalAlign="bottom" />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};

export default StorageView;
