import React from "react";

const SEVERITY_COLOR = {
  none:     "var(--sev-none)",
  low:      "var(--sev-low)",
  medium:   "var(--sev-medium)",
  high:     "var(--sev-high)",
  critical: "var(--sev-critical)",
  cyan:     "var(--cyan)",
  amber:    "var(--amber)",
  green:    "var(--green)",
  red:      "var(--red)",
};

export default function StatCard({ label, value, sub, color = "cyan", icon: Icon, trend }) {
  const c = SEVERITY_COLOR[color] || color;

  return (
    <div style={{
      background:   "var(--bg-card)",
      border:       `1px solid var(--border)`,
      borderTop:    `2px solid ${c}`,
      borderRadius: "4px",
      padding:      "20px 24px",
      position:     "relative",
      overflow:     "hidden",
      animation:    "slide-in 0.3s ease forwards",
    }}>
      {/* Background glow */}
      <div style={{
        position:   "absolute", top: 0, left: 0, right: 0, height: "60px",
        background: `linear-gradient(180deg, ${c}18 0%, transparent 100%)`,
        pointerEvents: "none",
      }} />

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{
            fontFamily:    "var(--font-label)",
            fontSize:      "11px",
            fontWeight:    600,
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            color:         "var(--text-secondary)",
            marginBottom:  "10px",
          }}>
            {label}
          </div>
          <div style={{
            fontFamily: "var(--font-mono)",
            fontSize:   "32px",
            color:      c,
            lineHeight: 1,
            animation:  "counter-up 0.4s ease forwards",
          }}>
            {value ?? "—"}
          </div>
          {sub && (
            <div style={{
              marginTop:  "6px",
              fontSize:   "12px",
              color:      "var(--text-muted)",
              fontFamily: "var(--font-mono)",
            }}>
              {sub}
            </div>
          )}
        </div>
        {Icon && (
          <div style={{
            width:        "40px", height: "40px",
            borderRadius: "4px",
            background:   `${c}18`,
            border:       `1px solid ${c}33`,
            display:      "flex",
            alignItems:   "center",
            justifyContent: "center",
          }}>
            <Icon size={18} color={c} />
          </div>
        )}
      </div>

      {trend !== undefined && (
        <div style={{
          marginTop:  "12px",
          paddingTop: "12px",
          borderTop:  "1px solid var(--border)",
          fontSize:   "11px",
          color:      trend > 0 ? "var(--red)" : "var(--green)",
          fontFamily: "var(--font-mono)",
        }}>
          {trend > 0 ? "▲" : "▼"} {Math.abs(trend)}% from last cycle
        </div>
      )}
    </div>
  );
}
