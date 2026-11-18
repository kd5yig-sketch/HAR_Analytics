/* ---------- statistics over time and per endpoint ---------- */
function percentile(sorted, p) { if (!sorted.length) return NaN; const k = (sorted.length - 1) * p, lo = Math.floor(k), hi = Math.ceil(k); return sorted[lo] + (sorted[hi] - sorted[lo]) * (k - lo); }
const NICE_STEPS = [100, 250, 500, 1000, 2000, 5000, 10000, 15000, 30000, 60000, 120000, 300000, 600000, 900000, 1800000, 3600000, 7200000, 21600000, 43200000, 86400000];
const outcomeOf = e => e.status === 0 ? 'failed' : e.status >= 500 ? '5xx' : e.status >= 400 ? '4xx' : 'ok';
// Buckets of equal duration covering the capture; each with counts by outcome, bytes and latency percentiles.
function timeBuckets(entries, target = 60) {
  const list = entries.filter(e => !isPending(e));
  const span = Math.max(1, list.reduce((a, e) => Math.max(a, e.start + e.time), 0));
  const step = NICE_STEPS.find(s => span / s <= target) || NICE_STEPS[NICE_STEPS.length - 1];
  const n = Math.max(1, Math.ceil(span / step));
  const B = Array.from({ length: n }, (_, k) => ({ from: k * step, to: (k + 1) * step, n: 0, ok: 0, '4xx': 0, '5xx': 0, failed: 0, bytes: 0, times: [] }));
  for (const e of list) { const b = B[Math.min(n - 1, Math.floor(e.start / step))]; b.n++; b[outcomeOf(e)]++; b.bytes += e.transfer; b.times.push(e.time); }
  for (const b of B) { b.times.sort((x, y) => x - y); b.p50 = percentile(b.times, 0.5); b.p95 = percentile(b.times, 0.95); b.errors = b['4xx'] + b['5xx'] + b.failed; delete b.times; }
  return { step, span, buckets: B };
}
function endpointStats(entries) {
  const m = new Map();
  for (const e of entries) {
    if (isPending(e)) continue;
    const k = cmpKey(e);
    if (!m.has(k)) m.set(k, { key: k, entries: [], times: [], bytes: 0, errors: 0, statuses: new Map() });
    const s = m.get(k); s.entries.push(e); s.times.push(e.time); s.bytes += e.transfer; if (isFail(e)) s.errors++; s.statuses.set(e.status, (s.statuses.get(e.status) || 0) + 1);
  }
  return [...m.values()].map(s => { s.times.sort((a, b) => a - b); return { key: s.key, entries: s.entries, count: s.entries.length, errors: s.errors, errorRate: s.errors / s.entries.length, p50: percentile(s.times, 0.5), p95: percentile(s.times, 0.95), max: s.times[s.times.length - 1], avgBytes: s.bytes / s.entries.length, statuses: [...s.statuses].sort((a, b) => b[1] - a[1]) }; });
}
// Plain-language observations about how the capture changed over time.
function timelineInsights(entries) {
  const out = [], list = entries.filter(e => !isPending(e)).sort((a, b) => a.start - b.start);
  if (list.length < 10) return out;
  const clock = ms => new Date(S.base + ms).toISOString().slice(11, 19);
  const rel = ms => '+' + (ms >= 60000 ? Math.floor(ms / 60000) + ':' + String(Math.floor(ms / 1000) % 60).padStart(2, '0') : (ms / 1000).toFixed(1) + ' s');
  // Error onset: the split point that best separates a low error rate before from a high one after.
  const fails = list.map(isFail), total = fails.filter(Boolean).length;
  if (total >= 3) {
    let best = null, before = 0;
    for (let k = 5; k < list.length - 3; k++) {
      before += fails[k - 1] ? 1 : 0;
      const rb = before / k, ra = (total - before) / (list.length - k);
      if (ra - rb >= 0.3 && (!best || ra - rb > best.gain)) best = { k, rb, ra, gain: ra - rb };
    }
    if (best) out.push({ kind: 'errors', at: list[best.k].start, text: 'Errors start at ' + rel(list[best.k].start) + ' (' + clock(list[best.k].start) + ' UTC): ' + Math.round(best.rb * 100) + '% of requests failed before, ' + Math.round(best.ra * 100) + '% after.' });
  }
  const third = Math.floor(list.length / 3), med = arr => percentile(arr.map(e => e.time).sort((a, b) => a - b), 0.5);
  const a = med(list.slice(0, third)), b = med(list.slice(-third));
  if (b > a * 2 && b - a > 200) out.push({ kind: 'latency', text: 'Requests got slower: median ' + fmtMs(a) + ' in the first third of the capture, ' + fmtMs(b) + ' in the last third.' });
  else if (a > b * 2 && a - b > 200) out.push({ kind: 'latency', text: 'Requests got faster: median ' + fmtMs(a) + ' in the first third, ' + fmtMs(b) + ' in the last third (warm caches or less load).' });
  const tb = timeBuckets(list, 60), peak = tb.buckets.reduce((x, y) => (y.n > x.n ? y : x), tb.buckets[0]);
  const medN = percentile(tb.buckets.map(x => x.n).sort((x, y) => x - y), 0.5);
  if (peak && peak.n >= 5 && peak.n > 2 * medN) out.push({ kind: 'peak', at: peak.from, text: 'Busiest moment: ' + peak.n + ' requests between ' + rel(peak.from) + ' and ' + rel(peak.to) + '.' });
  const eps = endpointStats(list).filter(s => s.count >= 3).sort((x, y) => y.p95 - x.p95);
  if (eps[0] && eps[0].p95 > 1000) out.push({ kind: 'slowest', text: 'Slowest endpoint (95th percentile): ' + eps[0].key + ' — ' + fmtMs(eps[0].p95) + ' over ' + eps[0].count + ' requests.' });
  const worst = endpointStats(list).filter(s => s.count >= 3 && s.errorRate >= 0.5).sort((x, y) => y.errors - x.errors);
  if (worst[0]) out.push({ kind: 'failing', text: 'Most failing endpoint: ' + worst[0].key + ' — ' + worst[0].errors + ' of ' + worst[0].count + ' failed (' + worst[0].statuses.map(([s, c]) => (s || 'failed') + ' ×' + c).join(', ') + ').' });
  return out;
}
