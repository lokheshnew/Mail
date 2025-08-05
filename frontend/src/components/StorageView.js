import React from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

const COLORS = ["#4285F4", "#34A853", "#FBBC05", "#EA4335", "#9C27B0"];

const StorageView = ({ storageInfo, emailStats }) => {
  const chartData = [
    { name: "Received", value: emailStats?.total_received || 0 },
    { name: "Sent", value: emailStats?.total_sent || 0 },
    { name: "Unread", value: emailStats?.unread_count || 0 },
    { name: "Drafts", value: emailStats?.draft_count || 0 },
    { name: "Deleted", value: emailStats?.deleted_count || 0 },
  ];

  return (
    <div className="storage-view">
      <div className="storage-card animate-fadeIn">
        <h2>Storage Usage</h2>
        {storageInfo && (
          <div className="storage-info">
            <div className="storage-bar">
              <div
                className="storage-fill"
                style={{ width: `${storageInfo.percentage}%` }}
              ></div>
            </div>
            <div className="storage-details">
              <span className="storage-used">
                📁 {storageInfo.used_mb} MB used
              </span>
              <span className={`badge badge-${storageInfo.status === 'ok' ? 'success' : storageInfo.status === 'warning' ? 'warning' : 'error'}`}>
                {storageInfo.status.toUpperCase()}
              </span>
            </div>
            <div className="storage-percentage">
              {storageInfo.percentage}%
            </div>
          </div>
        )}
      </div>

      {emailStats && (
        <div className="stats-card animate-fadeIn" style={{ animationDelay: '0.2s' }}>
          <h2>Email Statistics</h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) =>
                  `${name}: ${(percent * 100).toFixed(0)}%`
                }
                outerRadius={100}
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
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};

export default StorageView;