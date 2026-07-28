import { useState } from "react";
import Cat from "../components/Cat.jsx";

const NODES = [
  { role: "kali", label: "Kali attacker", iface: "eth1 · VMnet1 · 192.168.252.10" },
  { role: "ubuntu", label: "Ubuntu sensor", iface: "ens160 (data, passive RX) · ens33 (mgmt, VMnet8 NAT)" },
  { role: "windows", label: "Windows victim", iface: "Ethernet0 2 · VMnet1 · 192.168.252.20" },
];

const STATUS_LABEL = {
  ok: "ok",
  remote_error: "remote_error",
  ssh_error: "ssh_error",
  timeout: "timeout",
  local_error: "local_error",
  discovery_error: "discovery_error",
  powered_off: "powered_off",
};

function hostPill(hostResult) {
  if (!hostResult) return <span className="pill unknown">chưa probe</span>;
  const s = hostResult.status;
  const cls = s === "ok" ? "benign" : s === "powered_off" ? "unknown" : "critical";
  return <span className={`pill ${cls}`}>{STATUS_LABEL[s] || s}</span>;
}

export default function LabTopology({ setMascot }) {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [execResult, setExecResult] = useState(null);
  const [execLoading, setExecLoading] = useState(null);

  const refresh = async () => {
    setLoading(true);
    setMascot("scan", "Đang gọi labctl.py status — round-trip vmrun + SSH thật, có thể mất vài chục giây.");
    try {
      const res = await fetch("/api/lab/status");
      const data = await res.json();
      setStatus(data);
      const ok = data.document?.status === "ok";
      setMascot(ok ? "idle" : "alert", ok ? "Cả 3 VM phản hồi ok." : "Lab chưa sẵn sàng — xem chi tiết lỗi ở Lab Topology.");
    } finally {
      setLoading(false);
    }
  };

  const runExec = async (role, commandId) => {
    setExecLoading(`${role}:${commandId}`);
    try {
      const res = await fetch("/api/lab/exec", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role, command_id: commandId }),
      });
      setExecResult(await res.json());
    } finally {
      setExecLoading(null);
    }
  };

  const configPresent = status?.config_present;
  const doc = status?.document;

  return (
    <>
      <div className="banner info">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><path d="M12 8v5M12 16h.01" /></svg>
        <div>
          Gọi thật <span className="num">tools/labctl.py</span> qua subprocess — mỗi lần "Refresh" là một round-trip
          <span className="num"> vmrun getGuestIPAddress</span> + SSH thật, không cache giả. Exec chỉ cho phép 2 lệnh chẩn đoán
          whitelist cứng ở backend (<span className="num">hostname</span>, <span className="num">whoami</span>) — không có ô nhập lệnh tự do.
        </div>
      </div>

      {status && !configPresent && (
        <div className="banner stale">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.3 3.9L2.5 18a2 2 0 001.8 3h15.4a2 2 0 001.8-3L13.7 3.9a2 2 0 00-3.4 0z" /><path d="M12 9v4M12 17h.01" /></svg>
          <div><b>config/lab-hosts.json không tồn tại trong workspace này.</b> labctl trả về <span className="num">{doc?.status}</span>: <span className="num">{doc?.error}</span>. Tạo file này từ <span className="num">config/lab-hosts.example.json</span> trên máy có VMware để dùng tab này thật.</div>
        </div>
      )}

      <div className="card" style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
        <button className="btn primary" onClick={refresh} disabled={loading}>{loading ? "Đang probe…" : "⟳ Refresh trạng thái"}</button>
        {status && <div className="source-badge">overall: {doc?.status ?? "—"} · config: {status.config_source}</div>}
        <div style={{ flex: 1 }} />
        <Cat state={loading ? "scan" : "idle"} size={30} />
      </div>

      <div className="grid row-3">
        {NODES.map((n) => {
          const hostResult = doc?.hosts?.[n.role];
          return (
            <div className="card" key={n.role}>
              <div className="card-head">
                <div><div className="card-title">{n.label}</div><div className="card-sub">{n.iface}</div></div>
                {hostPill(hostResult)}
              </div>
              {hostResult && (
                <div className="kv" style={{ gridTemplateColumns: "90px 1fr", fontSize: 11.5 }}>
                  <div>Address</div><div>{hostResult.address ?? "—"}</div>
                  <div>Stage</div><div>{hostResult.stage}</div>
                  <div>Duration</div><div>{hostResult.duration_ms} ms</div>
                  {hostResult.error && <><div>Error</div><div style={{ color: "var(--sev-critical)" }}>{hostResult.error}</div></>}
                </div>
              )}
              <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                <button className="btn" disabled={execLoading === `${n.role}:hostname`} onClick={() => runExec(n.role, "hostname")}>
                  {execLoading === `${n.role}:hostname` ? "…" : "exec hostname"}
                </button>
                <button className="btn" disabled={execLoading === `${n.role}:whoami`} onClick={() => runExec(n.role, "whoami")}>
                  {execLoading === `${n.role}:whoami` ? "…" : "exec whoami"}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {execResult && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-title">Kết quả exec — {execResult.role} / {execResult.command}</div>
          <pre style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, marginTop: 8, whiteSpace: "pre-wrap", color: "var(--text-2)" }}>
            {JSON.stringify(execResult.document, null, 2)}
          </pre>
        </div>
      )}
    </>
  );
}
