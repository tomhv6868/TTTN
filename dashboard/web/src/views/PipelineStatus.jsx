import { useEffect, useMemo, useState } from "react";

const STATUS_CHIP_CLASS = {
  passed: "passed",
  "technical passed": "technical",
  accepted_for_demo: "demo",
  accepted_for_speed_run_demo: "speedrun",
  "passed demo, formal=false": "formalfalse",
  "reduced/speed-run": "reduced",
};

function statusChip(status) {
  const cls = STATUS_CHIP_CLASS[status];
  if (cls) {
    return <span className={`status-chip ${cls}`} style={chipStyle(cls)}>{status}</span>;
  }
  // raw receipt-index.json statuses (planned / in_progress / unverified_legacy / ...)
  return <span className="status-chip" style={{ borderColor: "var(--border)", color: "var(--text-3)" }}>{status}</span>;
}

function chipStyle(cls) {
  const map = {
    passed: { background: "#3e7cf41c", borderColor: "#3e7cf455", color: "#8fb3fb" },
    technical: { background: "#3e7cf40d", borderColor: "#3e7cf455", color: "#8fb3fb", borderStyle: "dashed" },
    demo: { background: "#a48bfa1c", borderColor: "#a48bfa55", color: "#c9bdfb", borderStyle: "dashed" },
    speedrun: { background: "#a48bfa0d", borderColor: "#a48bfa40", color: "#c9bdfb" },
    formalfalse: { background: "#7d8ea31c", borderColor: "#7d8ea355", color: "#aab6c3" },
    reduced: { background: "#56617033", borderColor: "#56617066", color: "#8d97a3" },
  };
  return map[cls] || {};
}

export default function PipelineStatus() {
  const [data, setData] = useState(null);
  const [statusFilter, setStatusFilter] = useState("all");
  const [phaseFilter, setPhaseFilter] = useState("all");

  useEffect(() => {
    fetch("/api/pipeline").then((r) => r.json()).then(setData).catch(() => {});
  }, []);

  const statuses = useMemo(() => (data ? [...new Set(data.rows.map((r) => r.status))].sort() : []), [data]);
  const phases = useMemo(() => (data ? [...new Set(data.rows.map((r) => r.phase))].sort((a, b) => Number(a) - Number(b)) : []), [data]);

  const rows = useMemo(() => {
    if (!data) return [];
    return data.rows.filter(
      (r) => (statusFilter === "all" || r.status === statusFilter) && (phaseFilter === "all" || r.phase === phaseFilter)
    );
  }, [data, statusFilter, phaseFilter]);

  if (!data) return <div className="card">Đang tải /api/pipeline…</div>;

  return (
    <>
      <div className="banner stale">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.3 3.9L2.5 18a2 2 0 001.8 3h15.4a2 2 0 001.8-3L13.7 3.9a2 2 0 00-3.4 0z" /><path d="M12 9v4M12 17h.01" /></svg>
        <div>{data.stale_notice} Nguồn chuẩn: <b>{data.curated_source}</b>. Nguồn thô: <span className="num">{data.index_source}</span>.</div>
      </div>

      <div className="card" style={{ marginBottom: 16, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} style={selectStyle}>
          <option value="all">Tất cả status ({data.rows.length})</option>
          {statuses.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={phaseFilter} onChange={(e) => setPhaseFilter(e.target.value)} style={selectStyle}>
          <option value="all">Tất cả phase</option>
          {phases.map((p) => <option key={p} value={p}>Phase {p}</option>)}
        </select>
        <div style={{ flex: 1 }} />
        <div className="source-badge">{rows.length}/{data.rows.length} dòng</div>
      </div>

      <div className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Task</th><th>Phase</th><th>Status</th><th>Receipt path</th><th>SHA-256</th><th>Nguồn</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.task} style={r.stale_suspect ? { opacity: 0.5 } : undefined} title={r.stale_suspect ? "Từ receipt-index.json, chưa đối chiếu tay — có thể stale" : ""}>
                  <td className="num">{r.task}</td>
                  <td>{r.phase}</td>
                  <td>{statusChip(r.status)}</td>
                  <td className="num" style={{ fontSize: 11 }}>{r.receipt_path || "—"}</td>
                  <td className="num" style={{ fontSize: 10.5 }} title={r.sha256 || ""}>{r.sha256 ? r.sha256.slice(0, 12) + "…" : "—"}</td>
                  <td style={{ fontSize: 11, color: "var(--text-3)" }}>{r.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

const selectStyle = {
  background: "var(--surface-2)",
  border: "1px solid var(--border)",
  color: "var(--text-1)",
  borderRadius: 8,
  padding: "7px 10px",
  fontSize: 12,
};
