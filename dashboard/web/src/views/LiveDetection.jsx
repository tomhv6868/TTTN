import { useEffect, useRef, useState } from "react";
import { normalizeAlertEvent } from '../lib/liveFamilyStats.js';

function decisionPill(ev, model) {
  const d = ev.decision;
  if (model === 'terminal') {
    const label = ev.terminal_class || (d === 'benign' ? 'Benign' : ev.candidate || d);
    return <span className={`pill ${d === 'benign' ? 'benign' : 'critical'}`}>{label}</span>;
  }
  if (d === "known_attack") return <span className="pill critical">known_attack</span>;
  if (d === "unknown_candidate") return <span className="pill unknown">unknown_candidate</span>;
  if (d === "uncertain") return <span className="pill medium">uncertain</span>;
  if (d === "benign") return <span className="pill benign">benign</span>;
  return <span className="pill benign">{d || "benign"}</span>;
}

const API = "/api/alerts/tail";

const STATUS_SHORT = {
  investigating: "điều tra",
  escalated: "escalated",
  reviewed: "reviewed",
};

const RANGE_SECONDS = { "1H": 3600, "6H": 21600, "24H": 86400, "7D": 604800 };

export default function LiveDetection({ setMascot, pushToast, openDrawer, alertStatus = {}, search = "", range = "Live" }) {
  const [rows, setRows] = useState([]);
  const [paused, setPaused] = useState(false);
  const [source, setSource] = useState(null);
  const [sourceKind, setSourceKind] = useState(null);
  const [model, setModel] = useState("f9");
  const [counts, setCounts] = useState({ known_attack: 0, unknown_candidate: 0, uncertain: 0, benign: 0 });
  const offsetRef = useRef(0);
  const pausedRef = useRef(false);
  const seqRef = useRef(0);
  const modelRef = useRef("f9");

  const [page, setPage] = useState(0);
  const PAGE_SIZE = 50;

  useEffect(() => { pausedRef.current = paused; }, [paused]);
  useEffect(() => {
    // switching model: reset stream + tail from the start of the other file
    modelRef.current = model;
    offsetRef.current = 0;
    setRows([]);
    setCounts({ known_attack: 0, unknown_candidate: 0, uncertain: 0, benign: 0 });
    setPage(0);
  }, [model]);

  useEffect(() => {
    let alive = true;
    async function poll() {
      if (!pausedRef.current) {
        try {
          const initialBacklog = offsetRef.current === 0;
          const res = await fetch(`${API}?offset=${offsetRef.current}&model=${modelRef.current}`);
          const data = await res.json();
          if (!alive) return;
          offsetRef.current = data.offset;
          setSource(data.source);
          setSourceKind(data.source_kind);
          if (data.events.length) {
            const withMeta = data.events.map((rawEvent) => {
              const ev = normalizeAlertEvent(rawEvent, modelRef.current);
              return { ...ev, __seq: ++seqRef.current, __ts: new Date((ev.ts || Date.now() / 1000) * 1000).toTimeString().slice(0, 8) };
            });
            setRows((prev) => [...withMeta.reverse(), ...prev].slice(0, 20000));
            setCounts((prev) => {
              const next = { ...prev };
              withMeta.forEach((ev) => { next[ev.decision] = (next[ev.decision] || 0) + 1; });
              return next;
            });
            if (!initialBacklog) {
              withMeta.forEach((ev) => {
                if (ev.decision === "known_attack") {
                  pushToast({ severity: "critical", title: "Known attack detected", body: `${ev.candidate} — confidence ${ev.confidence ?? "—"} · ${ev.run}` }, ev);
                  setMascot("alert", `<b style="color:var(--sev-critical)">known_attack</b> vừa xuất hiện — candidate ${ev.candidate}.`);
                } else if (ev.decision === "unknown_candidate") {
                  pushToast({ severity: "warn", title: "Unknown-candidate anomaly", body: `Top candidate ${ev.candidate} · ${ev.run}` }, ev);
                  setMascot("scan", `Đang theo dõi bất thường — top candidate <b>${ev.candidate}</b>.`);
                }
              });
            }
          }
        } catch {
          /* backend not reachable yet — surfaced via source===null banner below */
        }
      }
      if (alive) setTimeout(poll, 2200);
    }
    poll();
    return () => { alive = false; };
  }, [pushToast, setMascot]);

  const q = search.trim().toLowerCase();
  const rangeSec = RANGE_SECONDS[range];
  const nowSec = Date.now() / 1000;
  const visibleRows = rows.filter((ev) => {
    if (rangeSec && ev.ts && nowSec - ev.ts > rangeSec) return false;
    if (q) {
      const hay = `${ev.decision} ${ev.candidate} ${ev.source} ${ev.destination} ${ev.protocol} ${ev.run}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  visibleRows.sort((a, b) => (b.ts || 0) - (a.ts || 0) || b.__seq - a.__seq);
  const totalPages = Math.max(1, Math.ceil(visibleRows.length / PAGE_SIZE));
  const curPage = Math.min(page, totalPages - 1);
  const pageRows = visibleRows.slice(curPage * PAGE_SIZE, (curPage + 1) * PAGE_SIZE);

  return (
    <>
      <div className="banner warn">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.3 3.9L2.5 18a2 2 0 001.8 3h15.4a2 2 0 001.8-3L13.7 3.9a2 2 0 00-3.4 0z" /><path d="M12 9v4M12 17h.01" /></svg>
        <div>
          <b>{sourceKind === "real" ? "Đang tail detection thật từ replay." : "Đang tail demo log (chưa có replay)."}</b> Nguồn hiện tại: <span className="num">{source || "đang kết nối backend…"}</span>.
          {sourceKind !== "real" && " Demo log lặp lại 3 sự kiện đã có evidence (T8.5 golden PCAP + rehearsal hping3/ftp-patator) chỉ để minh hoạ giao diện. Khi replay scenario ghi vào run_log/full-flow-v1/live-detection.jsonl, backend tự chuyển sang tail file thật đó ở lượt poll kế tiếp."}
          {" "}<span className="num">unknown_candidate</span> không đồng nghĩa với định danh đúng loại tấn công.
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
        <div style={{ fontSize: 12, color: "var(--text-2)" }}>Model:</div>
        <div className="tabs" style={{ margin: 0 }}>
          <button className={`tab-btn ${model === "f9" ? "active" : ""}`} onClick={() => setModel("f9")}>Partial-flow F9 (13 family)</button>
          <button className={`tab-btn ${model === "terminal" ? "active" : ""}`} onClick={() => setModel("terminal")}>Terminal V1 (6 lớp)</button>
        </div>
        <div style={{ fontSize: 12, color: "var(--text-2)" }}>Nguồn:</div>
        <div className="source-badge">{source || "…"}</div>
        <button className="btn" onClick={() => setPaused((p) => !p)}>{paused ? "▶ Resume tail" : "⏸ Pause tail"}</button>
        <div style={{ flex: 1 }} />
        {model === 'terminal' ? (
          <>
            <div className="pill critical">{counts.known_attack || 0} attack</div>
            <div className="pill benign">{counts.benign || 0} benign</div>
          </>
        ) : (
          <>
            <div className="pill critical">{counts.known_attack || 0} known_attack</div>
            <div className="pill unknown">{counts.unknown_candidate || 0} unknown_candidate</div>
            <div className="pill medium">{counts.uncertain || 0} uncertain</div>
            <div className="pill benign">{counts.benign || 0} benign</div>
          </>
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <div className="card-title">Alert stream</div>
          <div className="card-sub">
            {visibleRows.length.toLocaleString("en-US")} alert · trang {curPage + 1}/{totalPages} · {paused ? "paused" : "poll 2.2s"}
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Time</th><th>Decision</th><th>Candidate</th><th>Confidence</th><th>Source</th><th>Destination</th><th>Proto</th><th>Run</th><th>Status</th></tr></thead>
            <tbody>
              {pageRows.map((ev) => (
                <tr key={ev.__seq} className="new-row" onClick={() => openDrawer(ev, ev.__ts)}>
                  <td className="num">{ev.__ts}</td>
                  <td>{decisionPill(ev, model)}</td>
                  <td>{ev.candidate}</td>
                  <td className="num">{ev.confidence ?? "—"}</td>
                  <td className="ip">{ev.source}</td>
                  <td className="ip">{ev.destination}</td>
                  <td>{ev.protocol}</td>
                  <td style={{ color: "var(--text-3)", fontSize: 11 }}>{ev.run}</td>
                  <td>
                    {alertStatus[ev.__seq]
                      ? <span className={`pill status-${alertStatus[ev.__seq]}`}>{STATUS_SHORT[alertStatus[ev.__seq]]}</span>
                      : <span style={{ color: "var(--text-3)" }}>—</span>}
                  </td>
                </tr>
              ))}
              {visibleRows.length === 0 && (
                <tr><td colSpan={9} style={{ color: "var(--text-3)", textAlign: "center", padding: 24 }}>
                  {rows.length === 0 ? "Đang chờ sự kiện đầu tiên từ backend…" : "Không có alert khớp bộ lọc search/range."}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
        {totalPages > 1 && (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, padding: "12px 0 2px" }}>
            <button className="btn" disabled={curPage === 0} onClick={() => setPage(0)}>« Đầu</button>
            <button className="btn" disabled={curPage === 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>‹ Trước</button>
            <span className="num" style={{ fontSize: 12 }}>Trang {curPage + 1} / {totalPages}</span>
            <button className="btn" disabled={curPage >= totalPages - 1} onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}>Sau ›</button>
            <button className="btn" disabled={curPage >= totalPages - 1} onClick={() => setPage(totalPages - 1)}>Cuối »</button>
          </div>
        )}
      </div>
    </>
  );
}
