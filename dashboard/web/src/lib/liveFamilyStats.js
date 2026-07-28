export function summarizeLiveFamilies(events = []) {
  const byFam = {};
  let total = 0;

  for (const ev of events) {
    const decision = String(ev?.decision ?? '').trim().toLowerCase();
    if (decision === 'benign') continue;

    const family = ev?.candidate || ev?.decision || '?';
    byFam[family] = (byFam[family] || 0) + 1;
    total += 1;
  }

  return { byFam, total };
}

const CANONICAL_DECISIONS = new Set([
  'known_attack',
  'unknown_candidate',
  'uncertain',
  'benign',
]);

export function normalizeAlertEvent(event, model) {
  if (model !== 'terminal') return event;

  const rawDecision = String(event?.decision ?? '').trim();
  const semanticDecision = rawDecision.toLowerCase();
  if (CANONICAL_DECISIONS.has(semanticDecision)) {
    return {
      ...event,
      decision: semanticDecision,
      terminal_class: event?.terminal_class
        || (semanticDecision === 'benign' ? 'Benign' : event?.candidate || rawDecision),
    };
  }

  return {
    ...event,
    decision: semanticDecision === 'benign' ? 'benign' : 'known_attack',
    terminal_class: rawDecision || event?.candidate || '?',
  };
}
