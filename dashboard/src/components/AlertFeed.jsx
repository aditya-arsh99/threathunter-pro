import React, { useState } from "react";
import { ShieldAlert, CheckCircle, XCircle } from "lucide-react";
import { acknowledgeAlert, dismissAlert } from "../api/client";

// ------------------------------------------------------------------
// Severity Badge
// ------------------------------------------------------------------
const SEV_COLORS = {
  none:     { bg: "#1a2a3a", text: "var(--sev-none)",     label: "NONE"     },
  low:      { bg: "#002a1a", text: "var(--sev-low)",      label: "LOW"      },
  medium:   { bg: "#2a1a00", text: "var(--sev-medium)",   label: "MED"      },
  high:     { bg: "#2a0e00", text: "var(--sev-high)",     label: "HIGH"     },
  critical: { bg: "#2a0010", text: "var(--sev-critical)", label: "CRIT"     },
};

export function SeverityBadge({ severity }) {
  const s = SEV_COLORS[severity?.toLowerCase()] || SEV_COLORS.none;
  return (
    <span style={{
      background:    s.bg,
      color:         s.text,
      border:        `1px solid ${s.text}44`,
      borderRadius:  "2px",
      padding:       "2px 7px",
      fontSize:      "10px",
      fontFamily:    "var(--font-mono)",
      fontWeight:    600,
      letterSpacing: "0.08em",
    }}>
      {s.label}
    </span>
  );
}


// ------------------------------------------------------------------
// Alert Feed
// ------------------------------------------------------------------
export function AlertFeed({ alerts = [], onRefresh }) {
  const [loading, setLoading] = useState({});

  const handleAck = async (alertId) => {
    setLoading(p => ({ ...p, [alertId]: "ack" }));
    try {
      await acknowledgeAlert(alertId, { acknowledged_by: "analyst" });
      onRefresh?.();
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(p => ({ ...p, [alertId]: null }));
    }
  };

  const handleDismiss = async (alertId) => {
    setLoading(p => ({ ...p, [alertId]: "dismiss" }));
    try {
      await dismissAlert(alertId);
      onRefresh?.();
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(p => ({ ...p, [alertId]: null }));
    }
  };

  return (
    <div style={{
      background:   "var(--bg-card)",
      border:       "1px solid var(--border)",
      borderTop:    "2px solid var(--red)",
      borderRadius: "4px",
      overflow:     "hidden",
    }}>
      {/* Header */}
      <div style={{
        padding:        "14px 20px",
        borderBottom:   "1px solid var(--border)",
        display:        "flex",
        alignItems:     "center",
        gap:            "10px",
        background:     "linear-gradient(180deg, #ff335512 0%, transparent 100%)",
      }}>
        <ShieldAlert size={16} color="var(--red)" />
        <span style={{ fontFamily: "var(--font-label)", fontSize: "12px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--text-primary)" }}>
          Live Alert Feed
        </span>
        <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-muted)" }}>
          {alerts.length} alerts
        </span>
      </div>

      {/* Alert rows */}
      <div style={{ maxHeight: "380px", overflowY: "auto" }}>
        {alerts.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: "12px" }}>
            NO ACTIVE ALERTS
          </div>
        ) : (
          alerts.map((alert, i) => (
            <div key={alert.alert_id || i} style={{
              padding:     "12px 20px",
              borderBottom: "1px solid var(--border)",
              display:     "grid",
              gridTemplateColumns: "auto 1fr auto",
              gap:         "12px",
              alignItems:  "center",
              background:  i % 2 === 0 ? "transparent" : "#ffffff04",
              animation:   "slide-in 0.2s ease forwards",
              animationDelay: `${i * 0.03}s`,
            }}>
              <SeverityBadge severity={alert.severity} />

              <div style={{ minWidth: 0 }}>
                <div style={{
                  fontFamily:   "var(--font-mono)",
                  fontSize:     "11px",
                  color:        "var(--text-primary)",
                  whiteSpace:   "nowrap",
                  overflow:     "hidden",
                  textOverflow: "ellipsis",
                }}>
                  {alert.description || `${alert.source_type} anomaly`}
                </div>
                <div style={{ display: "flex", gap: "12px", marginTop: "3px" }}>
                  <span style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                    {alert.src_ip || "—"} → {alert.dst_ip || alert.hostname || "—"}
                  </span>
                  {alert.mitre_technique && (
                    <span style={{ fontSize: "10px", color: "var(--cyan-dim)", fontFamily: "var(--font-mono)" }}>
                      {alert.mitre_technique}
                    </span>
                  )}
                  <span style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                    risk={alert.risk_score ?? "—"}
                  </span>
                </div>
              </div>

              {alert.status === "open" && (
                <div style={{ display: "flex", gap: "6px" }}>
                  <button
                    onClick={() => handleAck(alert.alert_id)}
                    disabled={!!loading[alert.alert_id]}
                    title="Acknowledge"
                    style={{
                      background: "transparent", border: "1px solid var(--sev-low)",
                      borderRadius: "2px", padding: "3px 6px", cursor: "pointer",
                      color: "var(--sev-low)", display: "flex", alignItems: "center",
                    }}
                  >
                    <CheckCircle size={12} />
                  </button>
                  <button
                    onClick={() => handleDismiss(alert.alert_id)}
                    disabled={!!loading[alert.alert_id]}
                    title="Dismiss"
                    style={{
                      background: "transparent", border: "1px solid var(--text-muted)",
                      borderRadius: "2px", padding: "3px 6px", cursor: "pointer",
                      color: "var(--text-muted)", display: "flex", alignItems: "center",
                    }}
                  >
                    <XCircle size={12} />
                  </button>
                </div>
              )}
              {alert.status !== "open" && (
                <span style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "var(--font-mono)", textTransform: "uppercase" }}>
                  {alert.status}
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}


// ------------------------------------------------------------------
// Top IPs Bar
// ------------------------------------------------------------------
export function TopIPs({ ips = [], title = "Top Source IPs" }) {
  const max = ips[0]?.count || 1;

  return (
    <div style={{
      background:   "var(--bg-card)",
      border:       "1px solid var(--border)",
      borderTop:    "2px solid var(--amber)",
      borderRadius: "4px",
      overflow:     "hidden",
    }}>
      <div style={{
        padding:      "14px 20px",
        borderBottom: "1px solid var(--border)",
        background:   "linear-gradient(180deg, #ffaa0012 0%, transparent 100%)",
      }}>
        <span style={{ fontFamily: "var(--font-label)", fontSize: "12px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase" }}>
          {title}
        </span>
      </div>
      <div style={{ padding: "12px 20px", display: "flex", flexDirection: "column", gap: "10px" }}>
        {ips.slice(0, 8).map((item, i) => (
          <div key={item.ip || i}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-primary)" }}>
                {item.ip}
              </span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--amber)" }}>
                {item.count}
              </span>
            </div>
            <div style={{ height: "3px", background: "var(--border)", borderRadius: "2px" }}>
              <div style={{
                height:       "3px",
                width:        `${(item.count / max) * 100}%`,
                background:   i < 3 ? "var(--red)" : "var(--amber)",
                borderRadius: "2px",
                transition:   "width 0.6s ease",
              }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
