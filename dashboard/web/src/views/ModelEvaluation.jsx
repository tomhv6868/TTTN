import { useState, useEffect } from "react";

export default function ModelEvaluation({ model }) {
  const [tab, setTab] = useState("f9");
  const [confusion, setConfusion] = useState(null);

  useEffect(() => {
    fetch("/api/confusion")
      .then((r) => r.ok ? r.json() : null)
      .then(setConfusion)
      .catch(() => setConfusion(null));
  }, []);

  if (!model) return <div className="card">Đang tải /api/model…</div>;

  const d = model.data || {};
  const f9 = d.f9_baseline;
  const t91 = d.t91_terminal_full_flow;
  const parity = d.parity;
  const verified = model.source_kind === "manifest_verified";

  if (!f9 || !t91 || !parity) {
    return (
      <div className="card">
        <div className="card-title">Model &amp; Evaluation</div>
        <p style={{ fontSize: 12.5, color: "var(--text-2)", marginTop: 10 }}>
          Không đọc được số liệu đánh giá theo định dạng mong đợi (thiếu
          <span className="num"> f9_baseline / t91_terminal_full_flow / parity</span>).
          Nguồn hiện tại: <span className="num">{model.source || "?"}</span> ·
          source_kind <span className="num">{model.source_kind || "?"}</span>.
        </p>
      </div>
    );
  }

  return (
    <>
      <div className="sealed-banner">
        TEST PARTITION: SEALED — feature reads = 0, metric reads = 0. Không hiển thị số liệu test.
      </div>
      <div className="banner info" style={{ fontSize: 11.5 }}>
        <svg viewBox="0 0 24 24" width="14" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><path d="M12 8v5M12 16h.01" /></svg>
        <div>Nguồn: <b>{verified ? "docs (đã đối chiếu khớp manifest.json thật)" : "documented fallback"}</b> — {model.source}. {model.note}</div>
      </div>

      <div className="tabs">
        <button className={`tab-btn ${tab === "f9" ? "active" : ""}`} onClick={() => setTab("f9")}>F9 baseline (54 feature)</button>
        <button className={`tab-btn ${tab === "t91" ? "active" : ""}`} onClick={() => setTab("t91")}>Terminal full-flow (T9.1)</button>
        <button className={`tab-btn ${tab === "parity" ? "active" : ""}`} onClick={() => setTab("parity")}>Parity</button>
        <button className={`tab-btn ${tab === "confusion" ? "active" : ""}`} onClick={() => setTab("confusion")}>Confusion</button>
      </div>

      {tab === "f9" && (
        <>
          <div className="grid row-3">
            <div className="card"><div className="card-title">Known-attack recall</div><div className="kpi-value" style={{ marginTop: 8 }}>{(f9.known_attack_recall.value * 100).toFixed(3)}%</div><div className="card-note">{f9.known_attack_recall.citation}</div></div>
            <div className="card"><div className="card-title">Unknown-family recall</div><div className="kpi-value" style={{ marginTop: 8 }}>{(f9.unknown_family_recall.value * 100).toFixed(3)}%</div><div className="card-note">{f9.unknown_family_recall.note}</div></div>
            <div className="card"><div className="card-title">Benign FPR</div><div className="kpi-value" style={{ marginTop: 8 }}>{(f9.benign_fpr.value * 100).toFixed(3)}%</div><div className="card-note">{f9.benign_fpr.citation}</div></div>
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title">Macro unknown-candidate recall sau fusion hiệu chuẩn</div>
            <p style={{ fontSize: 12.5, color: "var(--text-2)", margin: "10px 0 0" }}>
              {(f9.macro_unknown_candidate_recall_after_fusion.value * 100).toFixed(3)}% — PortScan case study riêng lẻ đạt {(f9.portscan_case_study_unknown_candidate_recall.value * 100).toFixed(0)}%.
              {" "}{f9.portscan_case_study_unknown_candidate_recall.note}
            </p>
          </div>
        </>
      )}

      {tab === "t91" && (
        <>
          <div className="grid row-3">
            <div className="card"><div className="card-title">Selected profile</div><div className="kpi-value" style={{ marginTop: 8 }}>{t91.selected_profile.value} / {t91.selected_profile.feature_count}</div><div className="card-note">threshold {t91.selected_threshold.value}</div></div>
            <div className="card"><div className="card-title">Validation attack recall</div><div className="kpi-value" style={{ marginTop: 8 }}>{(t91.validation_attack_recall.value * 100).toFixed(3)}%</div><div className="card-note">benign FPR {(t91.validation_benign_fpr.value * 100).toFixed(4)}%</div></div>
            <div className="card"><div className="card-title">Macro F1 (profile A)</div><div className="kpi-value" style={{ marginTop: 8 }}>{t91.validation_macro_f1_profile_a.value.toFixed(5)}</div><div className="card-note">FTP P/R {t91.ftp_precision.value}/{t91.ftp_recall.value.toFixed(4)} · PortScan P/R {t91.portscan_precision.value.toFixed(4)}/{t91.portscan_recall.value.toFixed(4)}</div></div>
          </div>
        </>
      )}

      {tab === "parity" && (
        <div className="card">
          <div className="card-title">Sai số xác suất so với tolerance {parity.tolerance}</div>
          <div className="errbar-wrap" style={{ marginTop: 14 }}>
            <div className="errbar-row">
              <div style={{ fontSize: 12, color: "var(--text-2)" }}>Python ONNX Runtime</div>
              <div className="errbar-track"><div className="errbar-fill" style={{ width: `${(parity.python_ort_max_abs_probability_error.value / parity.tolerance) * 100}%` }} /><div className="errbar-tol" /></div>
              <div className="num" style={{ fontSize: 11, textAlign: "right" }}>{parity.python_ort_max_abs_probability_error.value.toExponential(2)}</div>
            </div>
            <div className="errbar-row">
              <div style={{ fontSize: 12, color: "var(--text-2)" }}>Native C++ runtime</div>
              <div className="errbar-track"><div className="errbar-fill" style={{ width: `${(parity.native_max_abs_probability_error.value / parity.tolerance) * 100}%`, background: "var(--accent)" }} /><div className="errbar-tol" /></div>
              <div className="num" style={{ fontSize: 11, textAlign: "right" }}>{parity.native_max_abs_probability_error.value.toExponential(2)}</div>
            </div>
          </div>
          <div className="card-note">Vạch đỏ = tolerance {parity.tolerance}. Cả hai sai số đều &lt;3% của ngưỡng.</div>
        </div>
      )}

      {tab === "confusion" && (
        <>
          {confusion ? (
            <>
              <div className="banner info">
                <svg viewBox="0 0 24 24" fill="none" stroke="current" strokeWidth="2" width="14"><circle cx="12" cy="12" r="10" /><path d="M12 8v5M12 16h.01" /></svg>
                <div>
                  <b>Replay evidence — rebuild 2026-08-08</b> · Nguồn: {confusion.source}.<br />
                  {confusion.methodology && confusion.methodology.substring(0, 120)}
                </div>
              </div>
              <div className="grid row-2" style={{ marginBottom: 16 }}>
                <div className="card">
                  <div className="card-title">Online F9 accuracy</div>
                  <div className="kpi-value" style={{ color: confusion.online_accuracy < 0.6 ? "var(--sev-critical)" : "var(--text-1)" }}>
                    {confusion.online_accuracy ? `${(confusion.online_accuracy * 100).toFixed(1)}%` : "N/A"}
                  </div>
                  <div className="card-note">
                    {confusion.online_correct} / {confusion.online_total} alerts đúng family
                  </div>
                </div>
                <div className="card">
                  <div className="card-title">Offline F9 accuracy</div>
                  <div className="kpi-value" style={{ color: "var(--sev-critical)" }}>
                    {confusion.offline_accuracy ? `${(confusion.offline_accuracy * 100).toFixed(1)}%` : "N/A"}
                  </div>
                  <div className="card-note">
                    {confusion.offline_correct} / {confusion.offline_total} flows đúng family
                  </div>
                </div>
              </div>
              <div className="card">
                <div className="card-title">Per-family comparison</div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Case</th><th>GT</th>
                        <th>Online candidate</th><th>Online Acc</th>
                        <th>Offline candidate</th><th>✓?</th>
                        <th>Ghi chú</th>
                      </tr>
                    </thead>
                    <tbody>
                      {confusion.rows.map((r) => (
                        <tr key={r.case_id}>
                          <td><span className="num">{r.case_id}</span></td>
                          <td>{r.gt}</td>
                          <td>
                            {r.online.count > 0
                              ? <span style={{ color: r.online.correct ? "var(--sev-critical)" : "var(--sev-high)" }}>{r.online.top_candidate}</span>
                              : <span style={{ color: "var(--text-3)" }}>—</span>}
                          </td>
                          <td className="num">
                            {r.online.accuracy != null ? `${(r.online.accuracy * 100).toFixed(1)}%` : "—"}
                          </td>
                          <td>
                            {r.offline.candidate !== "N/A"
                              ? <span style={{ color: r.offline.correct ? "var(--sev-critical)" : "var(--sev-high)" }}>{r.offline.candidate}</span>
                              : <span style={{ color: "var(--text-3)" }}>N/A</span>}
                          </td>
                          <td>
                            {r.offline.correct === true ? <span className="pill critical">✓</span>
                             : r.offline.correct === false ? <span className="pill high">✗</span>
                             : <span style={{ color: "var(--text-3)" }}>—</span>}
                          </td>
                          <td style={{ fontSize: 11, color: "var(--text-2)" }}>
                            {r.note || (r.online.count === 0 ? "not replayed" : "")}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="card-note" style={{ marginTop: 8 }}>
                  Online = DPDK sensor trên live replay. Offline = nids_demo_replay trên 9-packet cut PCAP.
                  Online accuracy thấp với DoS GoldenEye vì tcpreplay không giữ precise inter-packet timing →
                  F9 không phân biệt được DoS variants.
                </div>
              </div>
            </>
          ) : (
            <div className="card">
              <div className="card-title">Confusion Matrix</div>
              <div className="card-note">Đang tải f9-3way-confusion.json...</div>
            </div>
          )}
        </>
      )}
    </>
  );
}
