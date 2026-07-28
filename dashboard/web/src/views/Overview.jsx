import { useEffect, useRef, useState } from "react";
import { summarizeLiveFamilies } from '../lib/liveFamilyStats.js';

const RECEIPT_COLORS = {
  passed: "#3e7cf4",
  in_progress: "#f4bd63",
  planned: "#566170",
  unverified_legacy: "#8b9aad",
  passed_demo_critical_path: "#a48bfa",
};

function DonutChart({ counts }) {
  const ref = useRef(null);
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const ctx = c.getContext("2d");
    const cx = 66, cy = 66, rOuter = 58, rInner = 36;
    const entries = Object.entries(counts);
    const total = entries.reduce((a, [, n]) => a + n, 0) || 1;
    let start = -Math.PI / 2;
    ctx.clearRect(0, 0, 132, 132);
    entries.forEach(([status, n]) => {
      const end = start + (n / total) * Math.PI * 2;
      ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, rOuter, start, end); ctx.closePath();
      ctx.fillStyle = RECEIPT_COLORS[status] || "#888";
      ctx.fill(); start = end;
    });
    ctx.globalCompositeOperation = "destination-out";
    ctx.beginPath(); ctx.arc(cx, cy, rInner, 0, Math.PI * 2); ctx.fill();
    ctx.globalCompositeOperation = "source-over";
    const style = getComputedStyle(document.documentElement);
    ctx.fillStyle = style.getPropertyValue("--text-1").trim();
    ctx.font = "700 20px " + style.getPropertyValue("--font-mono");
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillText(total, cx, cy - 6);
    ctx.font = "600 9px " + style.getPropertyValue("--font-ui");
    ctx.fillStyle = style.getPropertyValue("--text-3").trim();
    ctx.fillText("tasks", cx, cy + 10);
  }, [counts]);
  return <canvas ref={ref} width={132} height={132} />;
}

export default function Overview({ overview, model, setMascot }) {
  const [liveFam, setLiveFam] = useState(null);
  const [liveModel, setLiveModel] = useState("f9");
  const liveModelRef = useRef("f9");

  useEffect(() => {
    setMascot("idle", "Sensor F9-only đang giám sát.<br>Chưa có alert mới.");
  }, [setMascot]);

  useEffect(() => { liveModelRef.current = liveModel; setLiveFam(null); }, [liveModel]);

  useEffect(() => {
    let alive = true;
    async function poll() {
      try {
        const res = await fetch(`/api/alerts/tail?offset=0&model=${liveModelRef.current}`);
        const data = await res.json();
        if (!alive) return;
        const { byFam, total } = summarizeLiveFamilies(data.events);
        setLiveFam({ byFam, total, real: data.source_kind === "real" });
      } catch { /* backend not up yet */ }
      if (alive) setTimeout(poll, 3000);
    }
    poll();
    return () => { alive = false; };
  }, []);

  if (!overview) return <div className="card">Đang tải dữ liệu từ /api/overview…</div>;

  const receiptCounts = overview.receipt_status_counts || {};
  const rebuild = overview.rebuild_status;

  return (
    <>
      <div className="banner info">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><path d="M12 8v5M12 16h.01" /></svg>
        <div>
          <b>Real app — dữ liệu đọc trực tiếp từ file trong repo</b> qua FastAPI. Trạng thái dưới đây là
          lab <span className="num">rebuild 2026-08-08</span> (đã verify thật), không phải cache T9.1 cũ. Tab Live
          Detection tail <span className="num">run_log/full-flow-v1/live-detection.jsonl</span> khi replay ghi vào; chưa có
          thì hiện demo log.
        </div>
      </div>

      <div className="grid row-2" style={{ marginBottom: 16 }}>
        <div className="card">
          <div className="card-head">
            <div>
              <div className="card-title">{rebuild?.title || "Trạng thái rebuild"}</div>
              <div className="card-sub">{overview.rebuild_status_source || "rebuild_status.json"}</div>
            </div>
          </div>
          {rebuild ? (
            <>
              <div style={{ display: "flex", flexDirection: "column", gap: 7, marginTop: 4 }}>
                {rebuild.milestones.map((m, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 9, fontSize: 12.5 }}>
                    <span className={`pill ${m.status === "passed" ? "benign" : "medium"}`} style={{ minWidth: 62, justifyContent: "center" }}>
                      {m.status === "passed" ? "PASS" : "pending"}
                    </span>
                    <span style={{ color: "var(--text-2)" }}>{m.step}</span>
                  </div>
                ))}
              </div>
              <div className="card-note" style={{ marginTop: 10 }}>{rebuild.note}</div>
            </>
          ) : (
            <div className="card-note">Chưa có rebuild_status.json.</div>
          )}
        </div>

        <div className="card">
          <div className="card-head"><div><div className="card-title">Receipt governance</div><div className="card-sub">{overview.receipt_task_count} tasks, receipt-index.json</div></div></div>
          <div className="donut-wrap">
            <DonutChart counts={receiptCounts} />
            <div className="donut-legend">
              {Object.entries(receiptCounts).map(([status, n]) => (
                <div className="legend-row" key={status}>
                  <span className="legend-swatch" style={{ background: RECEIPT_COLORS[status] || "#888" }} />
                  {status}<span className="legend-val">{n}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-head" style={{ flexWrap: "wrap", gap: 10 }}>
          <div>
            <div className="card-title">Live detection — phân bố family (replay thật)</div>
            <div className="card-sub">{liveFam?.real ? `live-detection-${liveModel}.jsonl` : "demo"} · {(liveFam?.total || 0).toLocaleString("en-US")} alert · cập nhật 3s</div>
          </div>
          <div className="tabs" style={{ margin: 0 }}>
            <button className={`tab-btn ${liveModel === "f9" ? "active" : ""}`} onClick={() => setLiveModel("f9")}>F9 (13 family)</button>
            <button className={`tab-btn ${liveModel === "terminal" ? "active" : ""}`} onClick={() => setLiveModel("terminal")}>Terminal V1 (6 lớp)</button>
          </div>
        </div>
        {liveFam && liveFam.real && liveFam.total > 0 ? (
          <div className="bar-list">
            {Object.entries(liveFam.byFam).sort((a, b) => b[1] - a[1]).map(([name, n]) => (
              <div className="bar-row" key={name}>
                <div className="bar-name">{name}</div>
                <div className="bar-track"><div className="bar-fill" style={{ width: `${(n / liveFam.total) * 100}%`, background: "var(--sev-critical)" }} /></div>
                <div className="bar-val">{n.toLocaleString("en-US")}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="card-note">
            {liveModel === "terminal"
              ? "Terminal V1 chưa replay — chưa có alert thật (không hiển thị demo)."
              : "Chưa có detection thật."}
          </div>
        )}
      </div>

      {rebuild?.known_limits?.length > 0 && (
        <div className="card">
          <div className="card-head"><div><div className="card-title">Giới hạn đã biết</div><div className="card-sub">ghi rõ, không tô hồng</div></div></div>
          <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
            {rebuild.known_limits.map((l, i) => (
              <li key={i} style={{ fontSize: 12.5, color: "var(--text-2)", marginBottom: 6 }}>{l}</li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}
