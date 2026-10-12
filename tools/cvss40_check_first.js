// Score CVSS v4.0 vectors with FIRST's official calculator code (github.com/FIRSTdotorg/cvss-v4-calculator)
const fs = require('fs'), vm = require('vm'), path = require('path');
const dir = process.env.CVSS4_CALC_DIR || path.join(__dirname, 'cvss-v4-calculator');
const ctx = {console};
vm.createContext(ctx);
for (const f of ['cvss_config.js', 'cvss_lookup.js', 'max_severity.js', 'max_composed.js', 'cvss_score.js']) {
  vm.runInContext(fs.readFileSync(path.join(dir, f), 'utf8'), ctx, {filename: f});
}
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8')).filter(c => c.vector.startsWith('CVSS:4.0/'));
let ok = 0; const bad = [];
for (const c of cases) {
  ctx.vec = c.vector;
  const score = vm.runInContext(`(function(){
    const sel = {};
    for (const [t, td] of Object.entries(cvssConfig))
      for (const [g, gd] of Object.entries(td.metric_groups))
        for (const [mm, md] of Object.entries(gd)) sel[md.short] = md.selected;
    for (const part of vec.split('/').slice(1)) { const [k, v] = part.split(':'); sel[k] = v; }
    return cvss_score(sel, cvssLookup_global, maxSeverity, macroVector(sel));
  })()`, ctx);
  if (Math.abs(score - c.score) < 1e-9) ok++; else bad.push({vector: c.vector, expected: c.score, first: score});
}
console.log(JSON.stringify({checked: cases.length, agree: ok, disagree: bad}, null, 1));
