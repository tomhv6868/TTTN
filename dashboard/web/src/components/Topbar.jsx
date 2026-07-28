import { useEffect, useState } from "react";
import Cat from "./Cat.jsx";

const TITLES = {
  overview: "Overview",
  live: "Live Detection",
  model: "Model & Evaluation",
  lab: "Lab Topology",
  pipeline: "Pipeline Status",
};

export default function Topbar({ view, mascotState, theme, setTheme, hasNotif, onNotifClick, search, setSearch, range, setRange }) {
  const [sinceRefresh, setSinceRefresh] = useState(0);
  const liveView = view === "live";

  useEffect(() => {
    const t = setInterval(() => setSinceRefresh((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <header className="topbar">
      <div className="topbar-title">{TITLES[view] || view}</div>
      <label className="search" style={liveView ? undefined : { opacity: 0.45 }}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" /></svg>
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          disabled={!liveView}
          placeholder={liveView ? "Lọc IP, family, protocol, decision…" : "Search (chỉ ở Live Detection)"}
          style={{ border: "none", outline: "none", background: "transparent", color: "inherit", font: "inherit", width: "100%" }}
        />
      </label>
      <div className="range-group" style={liveView ? undefined : { opacity: 0.45 }}>
        {["Live", "1H", "6H", "24H", "7D"].map((r) => (
          <button key={r} className={`range-btn ${range === r ? "active" : ""}`} disabled={!liveView} onClick={() => setRange(r)}>{r}</button>
        ))}
      </div>
      <div className="live-pill"><span className="live-dot" />updated {sinceRefresh}s ago</div>
      <div className="topbar-spacer" />
      <button className="icon-btn" onClick={onNotifClick} title="Alert history">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 8a6 6 0 0112 0c0 7 3 9 3 9H3s3-2 3-9" /><path d="M13.7 21a2 2 0 01-3.4 0" /></svg>
        {hasNotif && <span className="notif-dot" />}
      </button>
      <button className="icon-btn" onClick={() => setTheme(theme === "light" ? "dark" : "light")} title="Toggle theme">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z" /></svg>
      </button>
      <Cat state={mascotState} size={30} title="System mascot" />
    </header>
  );
}
