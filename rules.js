(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory()
  else root.VibeAppDoctorRules = factory()
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict'

  const SEVERITIES = ['critical', 'high', 'medium', 'info']

  function lineOf(text, index) {
    return text.slice(0, Math.max(0, index)).split('\n').length
  }

  function lineText(text, line) {
    return (text.split('\n')[line - 1] || '').trim().slice(0, 180)
  }

  function add(findings, file, severity, title, why, fix, index, snippet, key) {
    const line = lineOf(file.text, index)
    const finding = { severity, title, file: file.name, line, why, fix }
    if (snippet) finding.snippet = snippet
    finding._key = key || [title, file.name, line].join('|')
    findings.push(finding)
  }

  function isClientFile(name) {
    return /(^|\/)(src\/|app\/|pages\/|components\/)|\.(tsx?|jsx?)$/i.test(name) && !/supabase\/functions|api\//i.test(name)
  }

  function isSql(file) {
    return /\.sql$/i.test(file.name) || /create\s+table|create\s+policy/i.test(file.text)
  }

  function decodeJwtPayload(token) {
    try {
      const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
      const padded = part + '='.repeat((4 - part.length % 4) % 4)
      const decoded = typeof atob === 'function' ? atob(padded) : Buffer.from(padded, 'base64').toString('utf8')
      return JSON.parse(decoded)
    } catch (_) { return null }
  }

  function redactSecret(value) {
    const clean = String(value).replace(/["'`\s].*$/, '')
    return `${clean.slice(0, 4)}… (${clean.length} characters)`
  }

  function looksLikeSecret(value) {
    return /^(sk_live_|sk-proj-|sk-)[A-Za-z0-9_-]{20,}|^AKIA[A-Z0-9]{16}$|^ghp_[A-Za-z0-9]{36}$|^-----BEGIN PRIVATE KEY-----/.test(value)
  }

  function analyze(files) {
    const normalized = (files || []).map(file => ({ name: file.name || 'pasted.txt', text: String(file.text || '') }))
    const findings = []
    const seen = new Set()
    const push = (...args) => {
      const before = findings.length
      add(findings, ...args)
      const current = findings[findings.length - 1]
      if (seen.has(current._key)) findings.splice(before, 1)
      else seen.add(current._key)
    }
    const allSql = normalized.filter(isSql).map(file => file.text).join('\n')

    for (const file of normalized) {
      const text = file.text
      const client = isClientFile(file.name)
      const envFile = /(^|\/)\.env(?:\.|$)/i.test(file.name)

      const serviceMatch = /(?:service_role|SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY)/i.exec(text)
      if (serviceMatch && client) push(file, 'critical', 'Supabase service role key in client code', 'The service role bypasses Row Level Security, so anyone running this app could act as an administrator.', 'Keep the service role key on a trusted server. Use the public anon key in the browser and enforce access with RLS.', serviceMatch.index, 'const serverOnly = process.env.SUPABASE_SERVICE_ROLE_KEY', 'service-client')
      const publicEnv = /(?:VITE_|NEXT_PUBLIC_)[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)/i.exec(text)
      if (publicEnv) push(file, 'critical', 'Secret exposed through a public environment variable', 'Vite and Next public variables are bundled into code that users can download.', 'Remove secrets from the public prefix. Read them only in a server side environment.', publicEnv.index, 'SERVER_SECRET=...  # keep this private', 'public-env')
      if (envFile) {
        const real = /(SUPABASE|SECRET|TOKEN|PASSWORD|KEY)\s*=\s*[^\s#]{8,}/i.exec(text)
        push(file, real ? 'high' : 'info', real ? 'Environment file is part of the pasted project' : 'Environment file is present', real ? 'A committed environment file can expose credentials through version history or a shared archive.' : 'Environment files often become secrets by accident when the project is shared.', real ? 'Remove it from version control, rotate exposed credentials, and use a local ignored file.' : 'Keep local environment files ignored and provide a documented example file.', real ? real.index : 0, undefined, 'env-file')
      }

      const jwtRe = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g
      let jwt
      while ((jwt = jwtRe.exec(text))) {
        const payload = decodeJwtPayload(jwt[0])
        if (payload && payload.role === 'service_role') push(file, 'critical', 'JWT grants the Supabase service role', 'This token has the service role role and can bypass Row Level Security.', 'Revoke this token and replace it with a server only credential. The public anon token is suitable for browser clients.', jwt.index, `REDACTED_SECRET = ${redactSecret(jwt[0])}`, 'jwt-service')
      }

      const secretRe = /(?:sk_live_[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN PRIVATE KEY-----)/g
      let secret
      while ((secret = secretRe.exec(text))) push(file, 'critical', 'Secret-like credential found in project text', `A credential beginning with ${redactSecret(secret[0])} is visible in the pasted file.`, 'Remove it from the repository, revoke it at the provider, and load a replacement from a private server environment.', secret.index, `REDACTED_SECRET = ${redactSecret(secret[0])}`, `secret-${secret[0].slice(0, 8)}`)

      if (isSql(file)) {
        const tableRe = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:(public)\.)?([\w"]+)/ig
        let table
        while ((table = tableRe.exec(text))) {
          const tableName = table[2].replace(/"/g, '')
          const rls = new RegExp(`alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:public\\.)?${tableName}\\s+enable\\s+row\\s+level\\s+security`, 'i')
          if ((table[1] || '').toLowerCase() === 'public' || !table[1]) {
            if (!rls.test(allSql)) push(file, 'high', `Public table ${tableName} has no RLS enable statement`, 'A table in an exposed schema can be read or changed with the anon key until Row Level Security is enabled.', `Enable RLS and add policies that match your ownership model. Example only, adapt the column and role names to this table.`, table.index, `alter table public.${tableName} enable row level security;\ncreate policy "Owners can access their rows" on public.${tableName}\n  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);`, `table-rls-${tableName}`)
          }
        }
        const policyRe = /create\s+policy\s+["']?([^"'\n]+)["']?\s+on\s+[^;]*?\s+for\s+(select|insert|update|delete|all)[^;]*?(?:to\s+(anon|public))?[^;]*?(using|with\s+check)\s*\(\s*true\s*\)/ig
        let policy
        while ((policy = policyRe.exec(text))) {
          const operation = policy[2].toLowerCase()
          const role = (policy[3] || 'public').toLowerCase()
          const write = ['insert', 'update', 'delete', 'all'].includes(operation)
          push(file, write ? 'high' : 'medium', `Overly broad ${operation} policy for ${role}`, 'A true policy grants access without checking who owns the row or what is being changed.', 'Replace true with an ownership or role condition. For writes, use a matching with check condition as well.', policy.index, 'using (auth.uid() = user_id) with check (auth.uid() = user_id)', `true-policy-${policy.index}`)
        }
        const missingCheck = /create\s+policy\s+[^;]*?\s+for\s+(insert|update)\b[^;]*/ig
        let noCheck
        while ((noCheck = missingCheck.exec(text))) if (!/with\s+check/i.test(noCheck[0])) push(file, 'medium', `Write policy is missing WITH CHECK`, 'A policy that controls visibility does not by itself validate new or changed row values.', 'Add a with check expression that enforces the same ownership rule as using.', noCheck.index, 'with check (auth.uid() = user_id)', `missing-check-${noCheck.index}`)
        const fnRe = /create\s+(?:or\s+replace\s+)?function[\s\S]*?security\s+definer[\s\S]*?(?=\$\$|;)/ig
        let fn
        while ((fn = fnRe.exec(text))) if (!/set\s+search_path/i.test(fn[0])) push(file, 'medium', 'SECURITY DEFINER function has no fixed search path', 'Without a fixed search path, an attacker may influence which objects the privileged function resolves.', 'Set an explicit search_path such as pg_catalog, public, or qualify every object name inside the function.', fn.index, 'set search_path = pg_catalog, public', `definer-path-${fn.index}`)
      }

      const xss = /(?:dangerouslySetInnerHTML\s*=|\.innerHTML\s*=\s*(?!["'`]))/i.exec(text)
      if (xss) push(file, 'high', 'Untrusted value is written into HTML', 'A non literal HTML value can execute attacker controlled markup in the browser.', 'Avoid raw HTML or sanitize the value with a trusted sanitizer before rendering it.', xss.index, 'element.textContent = value', 'xss')
      if (/Access-Control-Allow-Origin["']?\s*[:=]\s*["']\*["']/i.test(text) && /(authorization|cookie)/i.test(text)) push(file, 'medium', 'Wildcard CORS allows credentialed requests', 'A wildcard origin paired with authorization or cookies can expose an API to unintended browser callers.', 'Allow only the origins you trust and configure credentials deliberately.', Math.max(0, text.search(/Access-Control-Allow-Origin/i)), "Access-Control-Allow-Origin: https://your-app.example", 'cors')
      const http = /(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["'](http:\/\/[^"']+)/i.exec(text)
      if (http && !/http:\/\/(?:localhost|127\.0\.0\.1)(?::|\/)/i.test(http[1])) push(file, 'medium', 'Network request uses plain HTTP', 'Traffic sent over HTTP can be read or changed in transit.', 'Use HTTPS for deployed services and keep HTTP only for local development.', http.index, "fetch('https://api.example.test')", 'http')
      const storage = /(?:localStorage|sessionStorage)\.(?:setItem|set)\s*\(\s*["']([^"']*(?:token|password|secret|apiKey)[^"']*)["']/i.exec(text)
      if (storage) push(file, 'medium', 'Sensitive value is stored in browser storage', 'JavaScript accessible storage is exposed to any script that runs in the page.', 'Prefer an httpOnly secure cookie managed by the server, or keep short lived data in memory.', storage.index, "setItem('theme', 'dark')", 'storage')
      const dynamic = /\b(?:eval|new\s+Function)\s*\(/i.exec(text)
      if (dynamic) push(file, 'high', 'Dynamic code execution is present', 'eval and new Function can turn untrusted input into executable code.', 'Remove dynamic code execution and use explicit parsing or a safe lookup table.', dynamic.index, 'const handler = handlers[action]', 'dynamic-code')
      const log = /console\.log\s*\([^\n)]*\b(password|token|secret|apiKey)\b/i.exec(text)
      if (log) push(file, 'medium', 'Sensitive variable is logged', 'Logs are copied to consoles and monitoring systems where credentials can persist.', 'Remove the sensitive value from logs and log only a safe event name or request id.', log.index, 'console.log("request failed")', 'log-secret')
      if (/createClient\s*\([\s\S]*?anon/i.test(text) && /auth\.admin\b/i.test(text)) push(file, 'high', 'Anon client calls the Supabase admin API', 'The admin API requires a service role credential and must run on a trusted server.', 'Move the admin operation to a server side function using a protected service role key.', Math.max(0, text.search(/auth\.admin/i)), 'await supabase.auth.admin.listUsers()', 'anon-admin')
      const destructure = /const\s*\{\s*data\s*\}\s*=\s*await\s+supabase\.[^\n;]+/i.exec(text)
      if (destructure && !/error/i.test(destructure[0])) push(file, 'info', 'Supabase result ignores the error field', 'A failed request can look like an empty success when the returned error is never checked.', 'Destructure error too and handle it before using data.', destructure.index, 'const { data, error } = await supabase.from("items").select("*")', 'supabase-error')
      if (/package\.json$/i.test(file.name)) {
        const unstable = /["'][^"']+["']\s*:\s*["'](?:latest|\*)["']/i.exec(text)
        if (unstable) push(file, 'medium', 'Dependency version is not pinned', 'latest and wildcard versions can change the code you ship without a review.', 'Pin a tested version and update it deliberately with a lockfile.', unstable.index, '"react": "18.3.1"', 'dependency-version')
      }
    }

    const gitignore = normalized.find(file => /(^|\/)\.gitignore$/i.test(file.name))
    if (gitignore && !/(^|\n)\s*\.env(?:\b|$)/m.test(gitignore.text)) push(gitignore, 'high', '.gitignore does not ignore environment files', 'A future commit can include local credentials from a .env file.', 'Add .env and related environment file patterns to .gitignore, then rotate any credentials already committed.', 0, '.env', 'gitignore-env')
    return findings.map(({ _key, ...finding }) => finding).sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line)
  }

  function analyzeText(text) {
    const input = String(text || '')
    const header = /^---[ \t]+(.+?)[ \t]+---[ \t]*$/gm
    const matches = [...input.matchAll(header)]
    if (!matches.length) return analyze([{ name: 'pasted.txt', text: input }])
    const files = matches.map((match, index) => ({ name: match[1].trim(), text: input.slice(match.index + match[0].length, matches[index + 1] ? matches[index + 1].index : input.length) }))
    return analyze(files)
  }

  return { analyze, analyzeText, redactSecret }
})
