import Cat from "./Cat.jsx";

const IMPLEMENTED = [
  { id: "overview", label: "Overview", icon: <path d="M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z" /> },
  { id: "live", label: "Live Detection", icon: <path d="M12 2v4M12 18v4M4.9 4.9l2.8 2.8M16.3 16.3l2.8 2.8M2 12h4M18 12h4M4.9 19.1l2.8-2.8M16.3 7.7l2.8-2.8M12 9a3 3 0 100 6 3 3 0 000-6z" /> },
  { id: "model", label: "Model & Evaluation", icon: <path d="M3 3v18h18M7 15l4-6 3 3 5-8" /> },
  { id: "lab", label: "Lab Topology", icon: <path d="M3 4h18v12H3zM8 20h8M12 16v4" /> },
  { id: "pipeline", label: "Pipeline Status", icon: <path d="M9 3H5a2 2 0 00-2 2v4M15 3h4a2 2 0 012 2v4M9 21H5a2 2 0 01-2-2v-4M15 21h4a2 2 0 002-2v-4" /> },
];

export default function Sidebar({ view, setView, mascotState, footerMsg }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <Cat state="idle" size={34} title="NIDS mascot" />
        <div>
          <div className="brand-name">NIDS Ops</div>
          <div className="brand-sub">& evaluation</div>
        </div>
      </div>

      <div className="nav-group-label">Implemented</div>
      <ul className="nav">
        {IMPLEMENTED.map((item) => (
          <li key={item.id}>
            <button className={`nav-item ${view === item.id ? "active" : ""}`} onClick={() => setView(item.id)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">{item.icon}</svg>
              {item.label}
            </button>
          </li>
        ))}
      </ul>

      <div className="sidebar-foot">
        <div className="sidebar-cat-row">
          <Cat state={mascotState} size={30} />
          <div className="sidebar-cat-msg" dangerouslySetInnerHTML={{ __html: footerMsg }} />
        </div>
      </div>
    </aside>
  );
}
