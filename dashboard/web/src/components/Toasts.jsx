import { useCallback, useRef, useState } from "react";

let idCounter = 0;

export function useToasts() {
  const [toasts, setToasts] = useState([]);
  const timers = useRef({});

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, leaving: true } : t)));
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 220);
    clearTimeout(timers.current[id]);
  }, []);

  const push = useCallback(
    (toast) => {
      const id = ++idCounter;
      setToasts((prev) => {
        const next = [{ ...toast, id, leaving: false }, ...prev];
        return next.slice(0, 4);
      });
      timers.current[id] = setTimeout(() => dismiss(id), 6000);
      return id;
    },
    [dismiss]
  );

  return { toasts, push, dismiss };
}

const ICON = (
  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.4">
    <path d="M10.3 3.9L2.5 18a2 2 0 001.8 3h15.4a2 2 0 001.8-3L13.7 3.9a2 2 0 00-3.4 0z" />
    <path d="M12 9v4M12 17h.01" />
  </svg>
);

export default function ToastStack({ toasts, onDismiss, onClick }) {
  return (
    <div className="toast-stack">
      {toasts.map((t) => {
        const sevClass = t.severity === "critical" ? "" : `sev-${t.severity}`;
        const iconBg = t.severity === "critical" ? "#ef5a6322" : "#f4bd6322";
        const iconColor = t.severity === "critical" ? "var(--sev-critical)" : "var(--sev-medium)";
        return (
          <div
            key={t.id}
            className={`toast ${sevClass} ${t.leaving ? "leaving" : ""}`}
            onClick={() => onClick && onClick(t)}
          >
            <div className="toast-ic" style={{ background: iconBg, color: iconColor }}>{ICON}</div>
            <div style={{ flex: 1 }}>
              <div className="toast-title">{t.title}</div>
              <div className="toast-body">{t.body}</div>
            </div>
            <button
              className="toast-x"
              onClick={(e) => {
                e.stopPropagation();
                onDismiss(t.id);
              }}
            >
              ✕
            </button>
            <div className="toast-bar" />
          </div>
        );
      })}
    </div>
  );
}
