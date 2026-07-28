function decisionPill(d) {
  if (d === "known_attack") return <span className="pill critical">known_attack</span>;
  if (d === "unknown_candidate") return <span className="pill unknown">unknown_candidate</span>;
  return <span className="pill benign">benign</span>;
}

const STATUS_LABEL = {
  investigating: "Đang điều tra",
  escalated: "Đã báo cáo (escalated)",
  reviewed: "Đã xử lý (reviewed)",
};

export default function Drawer({ alert, ts, status, onMark, onClose }) {
  const open = !!alert;
  return (
    <>
      <div className={`scrim ${open ? "open" : ""}`} onClick={onClose} />
      <aside className={`drawer ${open ? "open" : ""}`}>
        <div className="drawer-head">
          <div>
            <div className="source-badge">THREAT INVESTIGATION</div>
            <div style={{ fontWeight: 800, fontSize: 15, marginTop: 2 }}>{alert ? alert.candidate : "Alert detail"}</div>
            {status && (
              <div className={`pill status-${status}`} style={{ marginTop: 6, display: "inline-block" }}>
                {STATUS_LABEL[status]}
              </div>
            )}
          </div>
          <button className="icon-btn" onClick={onClose}>✕</button>
        </div>
        {alert && (
          <>
            <div className="drawer-body">
              <div className="kv">
                <div>Timestamp</div><div>{ts}</div>
                <div>Decision</div><div>{decisionPill(alert.decision)}</div>
                <div>Candidate</div><div>{alert.candidate}</div>
                <div>Flow RF prob.</div><div>{alert.flow_rf_probability ?? "—"}</div>
                <div>Confidence</div><div>{alert.confidence ?? "—"}</div>
                <div>Source</div><div>{alert.source}</div>
                <div>Destination</div><div>{alert.destination}</div>
                <div>Protocol</div><div>{alert.protocol}</div>
                <div>Evidence run</div><div>{alert.run}</div>
              </div>
              <div className="section-label">Detection explanation</div>
              <div className="explain-box">{alert.explanation}</div>
              <div className="section-label">Interpretation limit</div>
              <div className="explain-box" style={{ borderColor: "#ef5a633a", background: "#ef5a6310" }}>
                unknown_candidate không đồng nghĩa với zero-day thực tế và không tự xác định attack family.
                Kết quả đo trong VMware chỉ có giá trị trong phạm vi phòng thí nghiệm.
              </div>
            </div>
            <div className="drawer-actions">
              <button
                className={`btn primary${status === "investigating" ? " active" : ""}`}
                onClick={() => onMark("investigating")}
              >
                Investigate
              </button>
              <button
                className={`btn${status === "escalated" ? " active" : ""}`}
                onClick={() => onMark("escalated")}
              >
                Escalate
              </button>
              <button
                className={`btn ghost${status === "reviewed" ? " active" : ""}`}
                onClick={() => onMark("reviewed")}
              >
                Mark reviewed
              </button>
            </div>
          </>
        )}
      </aside>
    </>
  );
}
