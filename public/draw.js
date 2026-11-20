// ===== Auslosung: N-regulärer gerichteter Graph mit Ausschlüssen =====
const Draw = (() => {
  function shuffle(a) {
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(rnd() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }
  function rnd() {
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      const u = new Uint32Array(1); crypto.getRandomValues(u); return u[0] / 4294967296;
    }
    return Math.random();
  }
  const key = (a, b) => a + ">" + b;

  // Max-Flow (Dinic) auf bipartitem Graph: Quelle -> Geber (N) -> Empfänger (1) -> Senke (N)
  function flowAssign(ids, N, forbid) {
    const p = ids.length, S = 2 * p, T = 2 * p + 1, V = 2 * p + 2;
    const g = Array.from({ length: V }, () => []);
    const to = [], cap = [];
    const add = (u, v, c) => {
      g[u].push(to.length); to.push(v); cap.push(c);
      g[v].push(to.length); to.push(u); cap.push(0);
    };
    for (let i = 0; i < p; i++) { add(S, i, N); add(p + i, T, N); }
    const giverOrder = shuffle([...Array(p).keys()]);
    for (const i of giverOrder) {
      for (const j of shuffle([...Array(p).keys()])) {
        if (i !== j && !forbid.has(key(ids[i], ids[j]))) add(i, p + j, 1);
      }
    }
    let level, it;
    const bfs = () => {
      level = new Array(V).fill(-1); level[S] = 0; const q = [S];
      while (q.length) { const u = q.shift(); for (const e of g[u]) if (cap[e] > 0 && level[to[e]] < 0) { level[to[e]] = level[u] + 1; q.push(to[e]); } }
      return level[T] >= 0;
    };
    const dfs = (u, f) => {
      if (u === T) return f;
      for (; it[u] < g[u].length; it[u]++) {
        const e = g[u][it[u]], v = to[e];
        if (cap[e] > 0 && level[v] === level[u] + 1) {
          const d = dfs(v, Math.min(f, cap[e]));
          if (d > 0) { cap[e] -= d; cap[e ^ 1] += d; return d; }
        }
      }
      return 0;
    };
    let flow = 0;
    while (bfs()) { it = new Array(V).fill(0); let f; while ((f = dfs(S, Infinity)) > 0) flow += f; }
    if (flow !== p * N) return null;
    const pairs = [];
    for (let i = 0; i < p; i++) for (const e of g[i]) {
      const v = to[e];
      if (v >= p && v < 2 * p && e % 2 === 0 && cap[e] === 0) pairs.push([ids[i], ids[v - p]]);
    }
    return pairs;
  }

  // Zufällige Kanten-Tausche zum Durchmischen (erhält Regularität und Regeln)
  function mix(pairs, forbid, rounds) {
    const set = new Set(pairs.map(([a, b]) => key(a, b)));
    const m = pairs.length;
    for (let r = 0; r < rounds; r++) {
      const x = Math.floor(rnd() * m), y = Math.floor(rnd() * m);
      if (x === y) continue;
      const [a, b] = pairs[x], [c, d] = pairs[y];
      if (a === d || c === b || a === c || b === d) continue;
      if (forbid.has(key(a, d)) || forbid.has(key(c, b))) continue;
      if (set.has(key(a, d)) || set.has(key(c, b))) continue;
      set.delete(key(a, b)); set.delete(key(c, d));
      set.add(key(a, d)); set.add(key(c, b));
      pairs[x] = [a, d]; pairs[y] = [c, b];
    }
    return pairs;
  }

  // hard/soft: Arrays von [von, zu]
  function run(ids, N, hard, soft) {
    if (N < 1 || ids.length < 2 || N > ids.length - 1) return null;
    const hardSet = new Set(hard.map(([a, b]) => key(a, b)));
    const both = new Set([...hardSet, ...soft.map(([a, b]) => key(a, b))]);
    let pairs = flowAssign(ids, N, both), usedSoft = true;
    if (!pairs) { pairs = flowAssign(ids, N, hardSet); usedSoft = false; }
    if (!pairs) return null;
    mix(pairs, usedSoft ? both : hardSet, pairs.length * 60 + 500);
    return { pairs, softRespected: usedSoft };
  }

  function maxN(ids, hard) {
    const hardSet = new Set(hard.map(([a, b]) => key(a, b)));
    for (let n = ids.length - 1; n >= 1; n--) if (flowAssign(ids, n, hardSet)) return n;
    return 0;
  }

  return { run, maxN, shuffle };
})();
if (typeof module !== "undefined") module.exports = Draw;
