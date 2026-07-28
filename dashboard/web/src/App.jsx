import { useCallback, useEffect, useState } from "react";
import Sidebar from "./components/Sidebar.jsx";
import Topbar from "./components/Topbar.jsx";
import Drawer from "./components/Drawer.jsx";
import ToastStack, { useToasts } from "./components/Toasts.jsx";
import Overview from "./views/Overview.jsx";
import LiveDetection from "./views/LiveDetection.jsx";
import ModelEvaluation from "./views/ModelEvaluation.jsx";
import LabTopology from "./views/LabTopology.jsx";
import PipelineStatus from "./views/PipelineStatus.jsx";

export default function App() {
  const [view, setView] = useState("overview");
  const [theme, setTheme] = useState(() => localStorage.getItem("nids-theme") || "");
  const [overview, setOverview] = useState(null);
  const [model, setModel] = useState(null);
  const [mascot, setMascotState] = useState({ state: "idle", msg: "Network looks quiet.<br>No suspicious activity right now." });
  const [search, setSearch] = useState("");
  const [range, setRange] = useState("Live");
  const [drawerAlert, setDrawerAlert] = useState(null);
  const [drawerTs, setDrawerTs] = useState(null);
  const [alertStatus, setAlertStatus] = useState({});
  const { toasts, push, dismiss } = useToasts();
  const [hasNotif, setHasNotif] = useState(false);

  const markAlert = useCallback(
    (seq, status) =>
      setAlertStatus((m) => (m[seq] === status ? m : { ...m, [seq]: status })),
    []
  );

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("nids-theme", theme);
  }, [theme]);

  useEffect(() => {
    fetch("/api/overview").then((r) => r.json()).then(setOverview).catch(() => {});
    fetch("/api/model").then((r) => r.json()).then(setModel).catch(() => {});
  }, []);

  const setMascot = useCallback((state, msg) => setMascotState({ state, msg }), []);

  const pushToast = useCallback(
    (toast, alertData) => {
      setHasNotif(true);
      push({ ...toast, __alert: alertData });
    },
    [push]
  );

  const openDrawer = (alert, ts) => { setDrawerAlert(alert); setDrawerTs(ts); };

  return (
    <div className="app">
      <Sidebar view={view} setView={setView} mascotState={mascot.state} footerMsg={mascot.msg} />
      <Topbar view={view} mascotState={mascot.state} theme={theme} setTheme={setTheme} hasNotif={hasNotif} onNotifClick={() => setHasNotif(false)} search={search} setSearch={setSearch} range={range} setRange={setRange} />
      <main className="main">
        {view === "overview" && <Overview overview={overview} model={model} setMascot={setMascot} />}
        {view === "live" && <LiveDetection setMascot={setMascot} pushToast={pushToast} openDrawer={openDrawer} alertStatus={alertStatus} search={search} range={range} />}
        {view === "model" && <ModelEvaluation model={model} />}
        {view === "lab" && <LabTopology setMascot={setMascot} />}
        {view === "pipeline" && <PipelineStatus />}
      </main>
      <Drawer
        alert={drawerAlert}
        ts={drawerTs}
        status={drawerAlert ? alertStatus[drawerAlert.__seq] : null}
        onMark={(s) => drawerAlert && markAlert(drawerAlert.__seq, s)}
        onClose={() => setDrawerAlert(null)}
      />
      <ToastStack
        toasts={toasts}
        onDismiss={dismiss}
        onClick={(t) => { if (t.__alert) openDrawer(t.__alert, new Date().toTimeString().slice(0, 8)); }}
      />
    </div>
  );
}
