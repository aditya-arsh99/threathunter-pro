import { useState, useEffect, useCallback } from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer,
} from "recharts";
import {
  Shield, Activity, AlertTriangle, Wifi, Terminal,
  RefreshCw, CheckCircle, Server, Database, Radio, Zap,
} from "lucide-react";

const API = "/api";
const REFRESH_MS = 30000;

const C = {
  cyan:"#00d9ff", green:"#00ff88", amber:"#f59e0b",
  red:"#ff3b5c", purple:"#a855f7", orange:"#ff7a3d", dim:"#5a7a96",
};
const SEV_COLOR = { critical:C.red, high:C.orange, medium:C.amber, low:C.cyan, none:C.dim };
const PIE_COLORS = [C.cyan, C.green, C.amber, C.red, C.purple, C.orange];

const sev  = (s) => (s||"none").toLowerCase();
const fmt  = (n) => n>=1e6?(n/1e6).toFixed(1)+"M":n>=1e3?(n/1e3).toFixed(1)+"K":String(n??0);
const time = (s) => s ? new Date(s).toLocaleTimeString() : "—";

function useFetch(url, deps=[]) {
  const [data,setData]=useState(null);
  const [loading,setLoading]=useState(true);
  const load = useCallback(async()=>{
    try{
      setLoading(true);
      const r=await fetch(API+url);
      if(r.ok) setData(await r.json());
    }catch(e){console.error(e);}
    finally{setLoading(false);}
  },[url]);
  useEffect(()=>{load();},[...deps]);
  return {data,loading,reload:load};
}

const Tip = ({active,payload,label}) => {
  if(!active||!payload?.length) return null;
  return (
    <div style={{background:"#111820",border:"1px solid #1e2d3d",padding:"8px 12px",borderRadius:2}}>
      {label&&<div style={{color:C.dim,fontSize:11,marginBottom:4}}>{label}</div>}
      {payload.map((p,i)=>(
        <div key={i} style={{color:p.color||C.cyan,fontSize:12}}>
          {p.name}: <strong>{fmt(p.value)}</strong>
        </div>
      ))}
    </div>
  );
};

function StatCard({icon:Icon,label,value,sub,color,pulse}){
  return(
    <div className="card fade-in" style={{padding:"16px 20px"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
        <div>
          <div style={{fontFamily:"var(--font-ui)",fontSize:10,letterSpacing:"0.15em",
            textTransform:"uppercase",color:"var(--text-dim)",marginBottom:6}}>{label}</div>
          <div style={{fontFamily:"var(--font-ui)",fontSize:32,fontWeight:700,
            color:color||C.cyan,lineHeight:1}}>{value}</div>
          {sub&&<div style={{fontSize:10,color:"var(--text-dim)",marginTop:4}}>{sub}</div>}
        </div>
        <div style={{width:36,height:36,borderRadius:4,display:"flex",alignItems:"center",
          justifyContent:"center",background:`${color||C.cyan}15`,
          border:`1px solid ${color||C.cyan}30`,
          animation:pulse?"pulse 2s infinite":"none"}}>
          <Icon size={18} color={color||C.cyan}/>
        </div>
      </div>
    </div>
  );
}

function SectionLabel({children}){
  return(
    <div style={{display:"flex",alignItems:"center",gap:8,margin:"20px 0 10px"}}>
      <div style={{width:3,height:14,background:C.cyan,borderRadius:2}}/>
      <span style={{fontFamily:"var(--font-ui)",fontSize:11,letterSpacing:"0.2em",
        textTransform:"uppercase",color:"var(--text-dim)"}}>{children}</span>
      <div style={{flex:1,height:1,background:"var(--border)"}}/>
    </div>
  );
}

function HealthDot({ok}){
  return(
    <span style={{display:"inline-block",width:7,height:7,borderRadius:"50%",
      background:ok?C.green:C.red,animation:ok?"pulse 2s infinite":"none",
      boxShadow:ok?`0 0 6px ${C.green}`:`0 0 6px ${C.red}`}}/>
  );
}

function Header({health,countdown,onRefresh,refreshing}){
  const esOk=health?.services?.elasticsearch?.status!=="unreachable";
  const rdOk=health?.services?.redis?.status==="ok";
  return(
    <header style={{borderBottom:"1px solid var(--border)",padding:"0 24px",
      background:"var(--surface)",position:"sticky",top:0,zIndex:100}}>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",height:52}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{position:"relative"}}>
            <Shield size={22} color={C.cyan}/>
            <span style={{position:"absolute",top:-2,right:-2,width:7,height:7,
              borderRadius:"50%",background:C.red,animation:"pulse 1.5s infinite",
              boxShadow:`0 0 6px ${C.red}`}}/>
          </div>
          <div>
            <div style={{fontFamily:"var(--font-ui)",fontSize:16,fontWeight:700,
              letterSpacing:"0.1em",color:"var(--text)"}}>
              THREATHUNTER <span style={{color:C.cyan}}>PRO</span>
            </div>
            <div style={{fontSize:9,color:"var(--text-dim)",letterSpacing:"0.2em",marginTop:-2}}>
              ML-POWERED THREAT DETECTION
            </div>
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:20}}>
          <div style={{display:"flex",gap:16}}>
            {[{label:"ELASTICSEARCH",ok:esOk},{label:"REDIS",ok:rdOk},{label:"ML ENGINE",ok:true}].map(({label,ok})=>(
              <div key={label} style={{display:"flex",alignItems:"center",gap:5}}>
                <HealthDot ok={ok}/>
                <span style={{fontSize:10,color:"var(--text-dim)",letterSpacing:"0.1em"}}>{label}</span>
              </div>
            ))}
          </div>
          <div style={{width:1,height:20,background:"var(--border)"}}/>
          <div style={{fontSize:10,color:"var(--text-dim)",letterSpacing:"0.05em"}}>
            REFRESH IN <span style={{color:C.amber}}>{countdown}s</span>
          </div>
          <button className="btn btn-sm" onClick={onRefresh}
            style={{display:"flex",alignItems:"center",gap:5}}>
            <RefreshCw size={11} style={{animation:refreshing?"spin 1s linear infinite":"none"}}/>
            REFRESH
          </button>
        </div>
      </div>
    </header>
  );
}

function AttackerIPs({data}){
  const items=(data?.network?.top_src_ips||[]).slice(0,8);
  const max=Math.max(...items.map(d=>d.count),1);
  const BAD=["185.220","194.165","45.33","198.98","91.108","77.247","23.129","171.25"];
  return(
    <div className="card" style={{height:"100%"}}>
      <div className="card-title"><Radio size={12} color={C.red}/>Top Source IPs</div>
      <div style={{padding:"12px 16px"}}>
        {items.map(d=>{
          const bad=BAD.some(p=>d.ip.startsWith(p));
          return(
            <div key={d.ip} style={{marginBottom:10}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                <span style={{fontSize:11,color:bad?C.red:"var(--text)"}}>
                  {bad&&<span style={{marginRight:4}}>⚠</span>}{d.ip}
                </span>
                <span style={{fontSize:11,color:C.dim}}>{fmt(d.count)}</span>
              </div>
              <div style={{height:3,background:"var(--border)",borderRadius:2}}>
                <div style={{width:`${(d.count/max)*100}%`,height:"100%",borderRadius:2,
                  background:bad?`linear-gradient(90deg,${C.red},${C.orange})`:`linear-gradient(90deg,#0088aa,${C.cyan})`,
                  transition:"width 0.5s ease"}}/>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function MitreChart({data}){
  const items=Object.entries(data?.windows?.by_mitre_tactic||{})
    .map(([k,v])=>({name:k,value:v}));
  return(
    <div className="card" style={{height:"100%"}}>
      <div className="card-title"><Zap size={12} color={C.purple}/>MITRE ATT&CK Tactics</div>
      <div style={{padding:"8px",height:180}}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={items} margin={{top:5,right:10,left:-20,bottom:40}}>
            <XAxis dataKey="name" tick={{fill:C.dim,fontSize:9,fontFamily:"var(--font-mono)"}}
              axisLine={false} tickLine={false} angle={-20} textAnchor="end"/>
            <YAxis tick={{fill:C.dim,fontSize:9}} axisLine={false} tickLine={false}/>
            <Tooltip content={<Tip/>}/>
            <Bar dataKey="value" fill={C.purple} radius={[2,2,0,0]} name="Events"/>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function SeverityDonut({data}){
  const items=Object.entries(data?.network?.by_severity||{})
    .filter(([,v])=>v>0)
    .map(([k,v])=>({name:k,value:v,color:SEV_COLOR[k]||C.dim}));
  return(
    <div className="card" style={{height:"100%"}}>
      <div className="card-title"><Activity size={12} color={C.amber}/>Network Severity</div>
      <div style={{display:"flex",alignItems:"center",padding:"8px 16px"}}>
        <div style={{width:130,height:130}}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={items} cx="50%" cy="50%" innerRadius={38} outerRadius={55}
                paddingAngle={2} dataKey="value">
                {items.map((e,i)=><Cell key={i} fill={e.color} stroke="transparent"/>)}
              </Pie>
              <Tooltip content={<Tip/>}/>
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div style={{flex:1,paddingLeft:12}}>
          {items.map(({name,value,color})=>(
            <div key={name} style={{display:"flex",justifyContent:"space-between",
              marginBottom:5,alignItems:"center"}}>
              <div style={{display:"flex",alignItems:"center",gap:6}}>
                <div style={{width:6,height:6,borderRadius:"50%",background:color}}/>
                <span style={{fontSize:10,textTransform:"uppercase",color:"var(--text-dim)"}}>{name}</span>
              </div>
              <span style={{fontSize:11,color}}>{fmt(value)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ProtocolChart({data}){
  const items=Object.entries(data?.network?.by_protocol||{})
    .map(([k,v])=>({name:k,value:v}));
  return(
    <div className="card" style={{height:"100%"}}>
      <div className="card-title"><Wifi size={12} color={C.cyan}/>Protocol Split</div>
      <div style={{padding:"8px",height:160}}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={items} cx="50%" cy="50%" outerRadius={60} dataKey="value"
              paddingAngle={3}
              label={({name,percent})=>`${name} ${(percent*100).toFixed(0)}%`}
              labelLine={false}>
              {items.map((_,i)=><Cell key={i} fill={PIE_COLORS[i%PIE_COLORS.length]} stroke="transparent"/>)}
            </Pie>
            <Tooltip content={<Tip/>}/>
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function AnomalyTrend({alertStats}){
  const items=(alertStats?.alerts_over_time||[]).slice(-24).map(d=>({
    time:new Date(d.timestamp).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}),
    count:d.count,
  }));
  if(!items.length) return(
    <div className="card" style={{height:"100%",display:"flex",alignItems:"center",
      justifyContent:"center",flexDirection:"column",gap:8,minHeight:200}}>
      <Terminal size={24} color="var(--text-faint)"/>
      <span style={{color:"var(--text-faint)",fontSize:11}}>NO ALERT HISTORY YET</span>
    </div>
  );
  return(
    <div className="card" style={{height:"100%"}}>
      <div className="card-title"><Activity size={12} color={C.green}/>Alert Timeline</div>
      <div style={{padding:"8px 0 0",height:170}}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={items} margin={{top:5,right:16,left:-20,bottom:0}}>
            <defs>
              <linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={C.cyan} stopOpacity={0.3}/>
                <stop offset="95%" stopColor={C.cyan} stopOpacity={0}/>
              </linearGradient>
            </defs>
            <XAxis dataKey="time" tick={{fill:C.dim,fontSize:9}} axisLine={false} tickLine={false}/>
            <YAxis tick={{fill:C.dim,fontSize:9}} axisLine={false} tickLine={false}/>
            <Tooltip content={<Tip/>}/>
            <Area type="monotone" dataKey="count" stroke={C.cyan} strokeWidth={1.5}
              fill="url(#ag)" name="Alerts"/>
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function EventIDTable({data}){
  const items=data?.windows?.top_event_ids||[];
  const NAMES={"4624":"Successful Logon","4625":"Failed Logon","4648":"Explicit Credentials",
    "4688":"Process Created","4698":"Scheduled Task","4720":"User Created",
    "4732":"Group Member Added","7045":"Service Installed","1102":"Audit Log Cleared"};
  return(
    <div className="card" style={{height:"100%"}}>
      <div className="card-title"><Terminal size={12} color={C.green}/>Windows Event IDs</div>
      {items.map(({event_id,count})=>(
        <div key={event_id} style={{display:"flex",justifyContent:"space-between",
          padding:"7px 16px",borderBottom:"1px solid var(--border)"}}>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <span style={{fontFamily:"var(--font-mono)",color:C.cyan,fontSize:12,minWidth:36}}>
              {event_id}
            </span>
            <span style={{fontSize:11,color:"var(--text-dim)"}}>
              {NAMES[event_id]||"Unknown"}
            </span>
          </div>
          <span style={{color:"var(--text)",fontSize:12}}>{fmt(count)}</span>
        </div>
      ))}
    </div>
  );
}

function AlertFeed({alerts,onAck}){
  const items=alerts?.alerts||[];
  return(
    <div className="card">
      <div className="card-title" style={{justifyContent:"space-between"}}>
        <span style={{display:"flex",alignItems:"center",gap:8}}>
          <AlertTriangle size={12} color={C.red}/>Live Alert Feed
        </span>
        <span style={{color:C.red,fontSize:11}}>{alerts?.total??0} TOTAL</span>
      </div>
      {!items.length?(
        <div style={{padding:"40px",textAlign:"center",color:"var(--text-faint)",fontSize:12}}>
          <CheckCircle size={28} color="var(--text-faint)"
            style={{margin:"0 auto 12px",display:"block"}}/>
          NO OPEN ALERTS — SYSTEM NOMINAL
        </div>
      ):(
        <div style={{overflowX:"auto"}}>
          <table style={{width:"100%",borderCollapse:"collapse"}}>
            <thead>
              <tr style={{borderBottom:"1px solid var(--border)"}}>
                {["SEVERITY","RISK","TYPE","DESCRIPTION","SRC IP","TIME","ACTION"].map(h=>(
                  <th key={h} style={{padding:"6px 12px",textAlign:"left",fontSize:9,
                    letterSpacing:"0.12em",color:"var(--text-faint)",fontWeight:600,
                    fontFamily:"var(--font-ui)"}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.slice(0,20).map((a,i)=>{
                const s=sev(a.severity);
                return(
                  <tr key={a.alert_id||i}
                    style={{borderBottom:"1px solid var(--border)"}}
                    onMouseEnter={e=>e.currentTarget.style.background="var(--surface2)"}
                    onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                    <td style={{padding:"8px 12px"}}>
                      <span className={`badge badge-${s}`}>{s}</span>
                    </td>
                    <td style={{padding:"8px 12px",color:C.amber}}>{a.risk_score??"—"}</td>
                    <td style={{padding:"8px 12px",color:"var(--text-dim)",fontSize:11}}>
                      {a.source_type?.toUpperCase()||"—"}
                    </td>
                    <td style={{padding:"8px 12px",fontSize:11,maxWidth:340,
                      overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                      {a.description||"—"}
                    </td>
                    <td style={{padding:"8px 12px",color:C.dim,fontSize:10}}>{a.src_ip||"—"}</td>
                    <td style={{padding:"8px 12px",color:C.dim,fontSize:10,whiteSpace:"nowrap"}}>
                      {time(a["@timestamp"])}
                    </td>
                    <td style={{padding:"8px 12px"}}>
                      {a.status==="open"?(
                        <button className="btn btn-sm"
                          onClick={()=>onAck(a.alert_id)}
                          style={{display:"flex",alignItems:"center",gap:4}}>
                          <CheckCircle size={10}/> ACK
                        </button>
                      ):(
                        <span style={{fontSize:10,color:C.green}}>✓ ACK</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function App(){
  const [tick,setTick]=useState(0);
  const [countdown,setCountdown]=useState(REFRESH_MS/1000);
  const [refreshing,setRefreshing]=useState(false);

  const {data:health}     = useFetch("/health",       [tick]);
  const {data:eventStats} = useFetch("/events/stats", [tick]);
  const {data:alertStats} = useFetch("/alerts/stats", [tick]);
  const {data:alerts}     = useFetch("/alerts?size=20&status=open",[tick]);

  useEffect(()=>{
    setCountdown(REFRESH_MS/1000);
    const iv=setInterval(()=>{
      setCountdown(c=>{
        if(c<=1){setTick(t=>t+1);return REFRESH_MS/1000;}
        return c-1;
      });
    },1000);
    return ()=>clearInterval(iv);
  },[tick]);

  const handleRefresh=()=>{setRefreshing(true);setTick(t=>t+1);setTimeout(()=>setRefreshing(false),800);};

  const handleAck=async(id)=>{
    if(!id) return;
    await fetch(`${API}/alerts/${id}/acknowledge`,{
      method:"PATCH",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({acknowledged_by:"analyst"}),
    });
    setTick(t=>t+1);
  };

  const net=eventStats?.network||{};
  const win=eventStats?.windows||{};
  const als=alertStats||{};

  return(
    <div style={{minHeight:"100vh"}}>
      <Header health={health} countdown={countdown}
        onRefresh={handleRefresh} refreshing={refreshing}/>
      <main style={{padding:"20px 24px 40px",maxWidth:1600,margin:"0 auto"}}>

        <SectionLabel>System Overview</SectionLabel>
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12}}>
          <StatCard icon={Database}      color={C.cyan}  label="Total Network Events"
            value={fmt(net.total_events)}    sub="indexed in elasticsearch"/>
          <StatCard icon={Activity}      color={C.amber} label="Network Anomalies"    pulse
            value={fmt(net.total_anomalies)} sub={`${net.anomaly_rate_pct??0}% rate`}/>
          <StatCard icon={AlertTriangle} color={C.red}   label="Open Alerts"          pulse={als.open_alerts>0}
            value={fmt(als.open_alerts)}     sub={`${als.total_alerts??0} total`}/>
          <StatCard icon={Server}        color={C.green} label="Windows Events"
            value={fmt(win.total_events)}    sub={`${win.total_anomalies??0} anomalies`}/>
        </div>

        <SectionLabel>Network Intelligence</SectionLabel>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12,marginBottom:12}}>
          <AttackerIPs    data={eventStats}/>
          <SeverityDonut  data={eventStats}/>
          <ProtocolChart  data={eventStats}/>
        </div>

        <SectionLabel>Windows Event Analysis</SectionLabel>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12,marginBottom:12}}>
          <EventIDTable data={eventStats}/>
          <MitreChart   data={eventStats}/>
          <AnomalyTrend alertStats={alertStats}/>
        </div>

        <SectionLabel>Active Threat Alerts</SectionLabel>
        <AlertFeed alerts={alerts} onAck={handleAck}/>

        <div style={{marginTop:24,display:"flex",justifyContent:"space-between",
          color:"var(--text-faint)",fontSize:10,letterSpacing:"0.1em"}}>
          <span>THREATHUNTER PRO v1.0.0 — ML-POWERED SOC PLATFORM</span>
          <span>ELASTICSEARCH · KAFKA · TENSORFLOW · FASTAPI</span>
        </div>
      </main>
    </div>
  );
}
