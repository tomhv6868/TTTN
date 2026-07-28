// Pixel-cat mascot, rendered as an SVG rect grid so it stays crisp at any
// size. State drives colour only (idle/scan/alert/sleep) via CSS classes
// defined in styles.css — no separate art asset per state.
const CAT_GRID = [
  [1,0,0,0,0,0,0,0,0,0,0,0,0,1],
  [1,1,0,0,0,0,0,0,0,0,0,0,1,1],
  [0,1,2,0,0,0,0,0,0,0,0,2,1,0],
  [0,1,1,1,1,1,1,1,1,1,1,1,1,0],
  [0,1,1,1,1,1,1,1,1,1,1,1,1,0],
  [0,1,1,4,4,4,4,4,4,4,4,1,1,0],
  [0,1,1,3,3,1,1,1,1,3,3,1,1,0],
  [0,1,1,1,1,1,5,5,1,1,1,1,1,0],
  [0,1,1,1,1,1,1,1,1,1,1,1,1,0],
  [0,0,1,1,1,1,1,1,1,1,1,1,0,0],
  [0,0,0,1,1,1,1,1,1,1,1,0,0,0],
  [0,0,0,0,1,1,1,1,1,1,0,0,0,0],
];
const CLASS_BY_VALUE = { 1: "px-fur", 2: "px-ear", 3: "px-eye", 4: "px-visor", 5: "px-nose" };
const COLS = CAT_GRID[0].length;
const ROWS = CAT_GRID.length;

export default function Cat({ state = "idle", size = 32, title }) {
  return (
    <svg
      viewBox={`0 0 ${COLS} ${ROWS}`}
      width={size}
      height={Math.round(size * (ROWS / COLS))}
      className={`cat-px cat state-${state}`}
      role="img"
      aria-label={title || `mascot cat, state ${state}`}
    >
      {title && <title>{title}</title>}
      {CAT_GRID.flatMap((row, y) =>
        row.map((v, x) =>
          v ? <rect key={`${x}-${y}`} x={x} y={y} width={1} height={1} className={CLASS_BY_VALUE[v]} /> : null
        )
      )}
      {state === "sleep" && (
        <text x={COLS - 3} y={2} fontSize={2.6} fill="var(--accent-2)" fontFamily="var(--font-pixel)">z</text>
      )}
    </svg>
  );
}
