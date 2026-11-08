(function () {
  const input = document.getElementById('input')
  const example = document.getElementById('example')
  const analyze = document.getElementById('analyze')
  const results = document.getElementById('results')
  const summary = document.getElementById('summary')
  const findingsEl = document.getElementById('findings')
  const fakeServiceJwt = [btoa('{"alg":"none"}'), btoa('{"role":"service_role","example":true}'), 'EXAMPLE_SIGNATURE'].join('.')
  const exampleText = `--- .env ---
VITE_SUPABASE_SERVICE_ROLE_KEY=EXAMPLE_SERVICE_ROLE_VALUE
STRIPE_SECRET=sk_live_EXAMPLE_NOT_REAL_123456789012345

--- .gitignore ---
node_modules
dist

--- src/integrations/supabase/client.ts ---
import { createClient } from '@supabase/supabase-js'
const supabase = createClient('https://example.supabase.co', '${fakeServiceJwt}')
export async function loadNotes() {
  const { data } = await supabase.from('notes').select('*')
  console.log('token', data)
  return data
}
const html = '<p>' + userInput + '</p>'
document.querySelector('#preview').innerHTML = html
localStorage.setItem('authToken', token)
eval(userInput)
fetch('http://api.example.com/notes')
fetch('http://localhost:54321/rest/v1/notes')

--- supabase/migrations/001_notes.sql ---
create table public.notes (id uuid primary key, user_id uuid, body text);
create policy "Anyone can read" on public.notes for select to anon using (true);
create policy "Anyone can add" on public.notes for insert to anon using (true);
create or replace function public.admin_note() returns void language plpgsql security definer as $$ begin null; end; $$;

--- supabase/functions/notes/index.ts ---
const headers = { 'Access-Control-Allow-Origin': '*', Authorization: request.headers.get('Authorization') }
`
  let currentFindings = []
  let currentFilter = 'all'

  function escapeHtml(value) { return String(value).replace(/[&<>"']/g, char => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#039;' }[char])) }
  function healthScore(findings) {
    const penalty = findings.reduce((sum, f) => sum + ({ critical: 25, high: 15, medium: 7, info: 2 }[f.severity] || 0), 0)
    return Math.max(0, 100 - penalty)
  }
  function markdown() {
    const score = healthScore(currentFindings)
    return `# Vibe App Doctor report\n\nHealth score: ${score}/100\n\n${currentFindings.map(f => `## ${f.severity.toUpperCase()}: ${f.title}\n\nLocation: ${f.file}:${f.line}\n\nWhy it matters: ${f.why}\n\nFix: ${f.fix}${f.snippet ? `\n\n\`\`\`\n${f.snippet}\n\`\`\`` : ''}`).join('\n\n')}`
  }
  function render() {
    const score = healthScore(currentFindings)
    const counts = ['critical', 'high', 'medium', 'info'].map(level => `${currentFindings.filter(f => f.severity === level).length} ${level}`).join(' · ')
    summary.innerHTML = `<div class="score" style="--score:${score}%"><div class="score-inner"><span class="score-number">${score}</span><span class="score-label">out of 100</span></div></div><div><h3>${currentFindings.length ? `${currentFindings.length} finding${currentFindings.length === 1 ? '' : 's'} to review` : 'No issues found'}</h3><p>${counts}</p><p class="formula">Formula: 100 minus 25 per critical, 15 per high, 7 per medium, and 2 per info finding, floored at 0.</p></div>`
    const visible = currentFindings.filter(f => currentFilter === 'all' || f.severity === currentFilter)
    if (!visible.length) { findingsEl.innerHTML = '<div class="empty">No findings match this filter.</div>'; return }
    const groups = ['critical', 'high', 'medium', 'info'].filter(level => visible.some(f => f.severity === level))
    findingsEl.innerHTML = groups.map(level => `<section class="finding-group"><h3 class="group-title">${level}</h3>${visible.filter(f => f.severity === level).map(f => `<article class="finding"><div class="finding-top"><span class="severity ${f.severity}">${f.severity}</span><h4>${escapeHtml(f.title)}</h4><span class="location">${escapeHtml(f.file)}:${f.line}</span></div><p><strong>Why it matters.</strong> ${escapeHtml(f.why)}</p><p><strong>Fix.</strong> ${escapeHtml(f.fix)}</p>${f.snippet ? `<pre>${escapeHtml(f.snippet)}</pre>` : ''}</article>`).join('')}</section>`).join('')
  }
  analyze.addEventListener('click', () => { currentFindings = window.VibeAppDoctorRules.analyzeText(input.value); currentFilter = 'all'; results.hidden = false; render(); results.scrollIntoView({ behavior: 'smooth', block: 'start' }) })
  example.addEventListener('click', () => { input.value = exampleText; input.focus() })
  document.querySelectorAll('.filter').forEach(button => button.addEventListener('click', () => { currentFilter = button.dataset.filter; document.querySelectorAll('.filter').forEach(item => item.classList.toggle('active', item === button)); render() }))
  document.getElementById('copy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(markdown()); document.getElementById('copy').textContent = 'Copied'; setTimeout(() => { document.getElementById('copy').textContent = 'Copy markdown' }, 1400) } catch (_) { window.prompt('Copy this report', markdown()) } })
  document.getElementById('print').addEventListener('click', () => window.print())
})()
