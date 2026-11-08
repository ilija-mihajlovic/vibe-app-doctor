# Vibe App Doctor

Vibe App Doctor is a dependency free, offline single page tool for reviewing files from AI built apps. It focuses on the patterns that commonly appear in React, Vite, Supabase, and edge function projects.

## Use it

Open `index.html` in a browser. Paste one file, or separate several files with headers in this form:

```text
--- src/integrations/supabase/client.ts ---
code here

--- supabase/migrations/001_init.sql ---
code here
```

Click Run the review. The tool analyzes the text in the page and does not make runtime network requests. It redacts detected credentials in findings. Load example fills the editor with a fictional project that demonstrates the checks.

## Test it

Run:

```sh
node --test
```

The suite uses Node 22 built in testing and has no package installation step.

## Checks

The analyzer reports these cases when the pasted text supports the finding.

1. Supabase service role use in client code, public environment variables, and pasted environment files. These can expose credentials in a browser or repository. Supabase service role credentials bypass Row Level Security.
2. JWT payloads with the service role role. A public anon role is allowed because it is intended for browser clients.
3. Known Stripe, OpenAI style, AWS, GitHub, and private key formats. These are credentials that should be revoked and replaced when exposed.
4. Public tables without an RLS enable statement. Exposed tables can be readable and writable with the anon key until access policies exist.
5. Public or anon policies using true. This removes the ownership check. Write access is high severity and read access is medium severity.
6. Insert and update policies without with check. A visibility condition does not validate new row values.
7. SECURITY DEFINER functions without a fixed search path. Object lookup can be influenced when privileged code uses an unsafe path.
8. Non literal HTML injection through innerHTML or dangerouslySetInnerHTML. Attacker controlled markup can run in the browser.
9. Wildcard CORS with authorization or cookies. A broad origin can make a credentialed API available to unintended callers.
10. Missing .env in .gitignore and pasted environment files. Local credentials can enter version history.
11. External HTTP requests. Traffic can be read or changed in transit.
12. Tokens, passwords, secrets, and API keys in browser storage. JavaScript running on the page can read them.
13. eval and new Function. They turn strings into executable code.
14. Logging sensitive variables. Logs can persist in consoles and monitoring systems.
15. Supabase admin API calls made by an anon client. Admin operations require a service role credential and a trusted server.
16. Supabase data results that ignore error. Failed requests can look like empty successes.
17. Unpinned package versions such as latest and *. Dependency updates can change shipped code without a deliberate review.

## Limits

This is a pattern review, not a proof of safety. It does not run the app, inspect a deployed database, validate authentication flows, check dependency advisories, or understand business authorization rules. A clean report means that these text patterns were not found in the pasted files. Test the live app and database before relying on it.

The health score is shown on the results page. It is a transparent calculation of 100 minus 25 per critical finding, 15 per high finding, 7 per medium finding, and 2 per info finding, with a floor of 0. It is a review aid, not a security certification.

## License

MIT. Copyright Ilija Mihajlovic.
