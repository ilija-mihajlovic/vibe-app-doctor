const test = require('node:test')
const assert = require('node:assert')
const rules = require('../rules.js')

test('missing WITH CHECK is reported on the line of its own policy', () => {
  const sql = [
    'alter table t enable row level security;',
    'create policy "read own" on t for select using (auth.uid() = user_id);',
    'create policy "update own" on t for update using (auth.uid() = user_id);'
  ].join('\n')
  const out = rules.analyze ? rules.analyze([{ name: 'a.sql', text: sql }]) : null
  assert.ok(out, 'analyze exists')
  const list = out.findings || out
  const f = list.find(x => /WITH CHECK/.test(x.title))
  assert.ok(f, 'finding present')
  assert.strictEqual(f.line, 3)
})
