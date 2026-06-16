import React from "react";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  AreaChart, Area,
} from "recharts";

// ------------------------------------------------------------------
// Shared panel wrapper
// ------------------------------------------------------------------
function Panel({ title, accent = "var(--cyan)", children }) {
  return (
    <div style={{
      background:   "var(--bg-card)",
      border:       "1px solid var(--border)",
      borderTop:    `2px solid ${accent}`,
      borderRadius: "4px",
      overflow:     "hidden",
      height:       "100%",
    }}>
      <div style={{
        padding:      "14px 20px",
        borderBottom: "1px solid var(--border)",
        background:   `linear-gradient(180deg, ${accent}12 0%, transparent 100%)`,
        fontFamily:   "var(--font-label)",
        fontSize:     "12px",
        fontWeight:   600,
        letterSpacing: "0.1em",
        textTransform: "uppercase",
      }}>
        {title}
      </div>
      <div style={{ padding: "16px 20px" }}>{children}</div>
    </div>
  );
}

// ------------------------------------------------------------------
// Custom tooltip
// ------------------------------------------------------------------
const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background:   "var(--bg-deep)",
      border:       "1px solid var(--border-bright)",
      borderRadius: "4px",
      padding:      "8px 12px",
      fontFamily:   "var(--font-mono)",
      fontSize:     "11px",
      color:        "var(--text-primary)",
    }}>
      {label && <div style={{ color: "var(--text-secondary)", marginBottom: "4px" }}>{label}</div>}
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color || "var(--cyan)" }}>
          {p.name}: {typeof p.value === "number" ? p.value.toLocaleString() : p.value}
        </div>
      ))}
    </div>
  );
};

// ------------------------------------------------------------------
// Severity Donut
// ------------------------------------------------------------------
const SEV_PALETTE = {
  none:     "var(--sev-none)",
  low:      "var(--sev-low)",
  medium:   "var(--sev-medium)",
  high:     "var(--sev-high)",
  critical: "var(--sev-critical)",
};

export function SeverityDonut({ data = {} }) {
  const order  = ["critical", "high", "medium", "low", "none"];
  const points = order
    .filter(k => data[k] > 0)
    .map(k => ({ name: k.toUpperCase(), value: data[k], color: SEV_PALETTE[k] }));

  const total = points.reduce((s, p) => s + p.value, 0);

  return (
    <Panel title="Alerts by Severity" accent="var(--red)">
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie
            data={points}
            cx="50%" cy="50%"
            innerRadius={55} outerRadius={85}
            paddingAngle={2}
            dataKey="value"
          >
            {points.map((p, i) => (
              <Cell key={i} fill={p.color} stroke="var(--bg-card)" strokeWidth={2} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      {/* Legend */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", justifyContent: "center" }}>
        {points.map((p, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: "5px" }}>
            <div style={{ width: "8px", height: "8px", borderRadius: "2px", background: p.color }} />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-secondary)" }}>
              {p.name} ({p.value})
            </span>
          </div>
        ))}
      </div>
    </Panel>
  );
}


// ------------------------------------------------------------------
// Protocol Breakdown
// ------------------------------------------------------------------
const PROTO_COLORS = ["var(--cyan)", "var(--green)", "var(--amber)", "var(--purple)"];

export function ProtocolChart({ data = {} }) {
  const points = Object.entries(data).map(([k, v]) => ({ name: k, value: v }));

  return (
    <Panel title="Network Protocols" accent="var(--cyan)">
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie
            data={points}
            cx="50%" cy="50%"
            outerRadius={80}
            paddingAngle={3}
            dataKey="value"
            label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
            labelLine={false}
          >
            {points.map((_, i) => (
              <Cell key={i} fill={PROTO_COLORS[i % PROTO_COLORS.length]} stroke="var(--bg-card)" strokeWidth={2} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
        </PieChart>
      </ResponsiveContainer>
    </Panel>
  );
}


// ------------------------------------------------------------------
// MITRE Tactics Horizontal Bar
// ------------------------------------------------------------------
export function MitreTactics({ network = {}, windows = {} }) {
  const merged = {};
  Object.entries(network).forEach(([k, v]) => { merged[k] = (merged[k] || 0) + v; });
  Object.entries(windows).forEach(([k, v]) => { merged[k] = (merged[k] || 0) + v; });

  const data = Object.entries(merged)
    .filter(([k]) => k !== "unknown")
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, value]) => ({ name: name.replace(" ", "\n"), value }));

  return (
    <Panel title="MITRE ATT&CK Tactics" accent="var(--purple)">
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
          <XAxis
            type="number"
            tick={{ fontFamily: "var(--font-mono)", fontSize: 10, fill: "var(--text-muted)" }}
            axisLine={false} tickLine={false}
          />
          <YAxis
            type="category" dataKey="name" width={130}
            tick={{ fontFamily: "var(--font-mono)", fontSize: 10, fill: "var(--text-secondary)" }}
            axisLine={false} tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: "var(--bg-hover)" }} />
          <Bar dataKey="value" name="Events" fill="var(--purple)" radius={[0, 2, 2, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </Panel>
  );
}


// ------------------------------------------------------------------
// Anomaly Rate Area Chart (over time)
// ------------------------------------------------------------------
export function AnomalyTimeline({ data = [] }) {
  return (
    <Panel title="Alert Volume Over Time" accent="var(--cyan)">
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data} margin={{ top: 5, right: 5, bottom: 5, left: 0 }}>
          <defs>
            <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="var(--cyan)"   stopOpacity={0.3} />
              <stop offset="95%" stopColor="var(--cyan)"   stopOpacity={0}   />
            </linearGradient>
            <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="var(--red)"    stopOpacity={0.4} />
              <stop offset="95%" stopColor="var(--red)"    stopOpacity={0}   />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
          <XAxis
            dataKey="timestamp"
            tick={{ fontFamily: "var(--font-mono)", fontSize: 9, fill: "var(--text-muted)" }}
            tickFormatter={t => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
            axisLine={false} tickLine={false} interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fontFamily: "var(--font-mono)", fontSize: 10, fill: "var(--text-muted)" }}
            axisLine={false} tickLine={false} width={30}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area
            type="monotone" dataKey="count" name="Alerts"
            stroke="var(--cyan)" strokeWidth={2}
            fill="url(#alertGrad)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </Panel>
  );
}


// ------------------------------------------------------------------
// Top Destination Ports
// ------------------------------------------------------------------
const PORT_NAMES = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
  53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB",
  3389: "RDP", 4444: "Meterp", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
};

export function TopPorts({ ports = [] }) {
  const data = ports.slice(0, 10).map(p => ({
    name:  PORT_NAMES[p.port] ? `${p.port} (${PORT_NAMES[p.port]})` : String(p.port),
    value: p.count,
    fill:  [4444, 1337, 31337].includes(p.port) ? "var(--red)" :
           [22, 23, 3389, 445].includes(p.port) ? "var(--amber)" :
           "var(--cyan-dim)",
  }));

  return (
    <Panel title="Top Destination Ports" accent="var(--amber)">
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ top: 5, right: 5, bottom: 40, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
          <XAxis
            dataKey="name"
            tick={{ fontFamily: "var(--font-mono)", fontSize: 9, fill: "var(--text-muted)", angle: -45, textAnchor: "end" }}
            axisLine={false} tickLine={false}
          />
          <YAxis
            tick={{ fontFamily: "var(--font-mono)", fontSize: 10, fill: "var(--text-muted)" }}
            axisLine={false} tickLine={false} width={30}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: "var(--bg-hover)" }} />
          <Bar dataKey="value" name="Hits" radius={[2, 2, 0, 0]}>
            {data.map((d, i) => (
              <Cell key={i} fill={d.fill} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </Panel>
  );
}
