# ECSA Online E-Voting System

Firebase-free student election platform using:
- GitHub Pages: static frontend hosting
- Cloudflare Workers: API and trusted server-side rules
- Cloudflare D1: relational database
- Cloudflare R2: candidate photographs and PDF manifestos

## Important production notes

This is a deployable starter implementation, not a certified election product. Run the acceptance/security tests in `SECURITY-CHECKLIST.md` and arrange an independent review before a real student election. The surname-as-password requirement is weak: surnames are guessable. Prefer one-time activation links or a strong first-login password reset. The implementation hashes the surname password with PBKDF2 but does not make a guessable password strong.

Ballots are stored separately from voter-position receipts. The receipt table identifies that a voter has voted for a position; the ballot table does not contain the voter's ID. This reduces direct linkage but is not a guarantee of cryptographic anonymity: administrators with database access may correlate timing. For high-stakes elections, commission an independent secret-ballot design review.

## 1. Create Cloudflare resources

1. Create a Cloudflare account.
2. Install Node.js (LTS) on your computer.
3. Open a terminal in the `worker` directory and run:
   ```bash
   npm install -g wrangler
   wrangler login
   wrangler d1 create ecsa-election-db
   wrangler r2 bucket create ecsa-election-files
   ```
4. Copy the D1 `database_id` from the command output into `worker/wrangler.toml`.
5. Create the schema:
   ```bash
   wrangler d1 execute ecsa-election-db --remote --file=schema.sql
   ```
6. Configure the GitHub Pages origin in `wrangler.toml`, e.g. `https://YOUR-USERNAME.github.io`.
7. Deploy the API:
   ```bash
   wrangler deploy
   ```
8. Set the one-time admin setup secret:
   ```bash
   wrangler secret put ADMIN_SETUP_KEY
   ```
   Enter a long random secret. Do not put this secret in GitHub or frontend files.
9. Set `ENVIRONMENT` to production if you use it for error-detail control:
   ```bash
   wrangler secret put ENVIRONMENT
   ```
   Enter `production`.

## 2. Create the two official accounts

After deployment, make two POST requests to:
`https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/api/setup-admin`

Header: `Content-Type: application/json` and `X-Setup-Key: YOUR_SECRET`

President body:
```json
{"role":"president","fullName":"Current ECSA President","email":"president@example.com","password":"Use-A-Unique-Long-Password"}
```

Election Chairman body:
```json
{"role":"election_chairman","fullName":"Election Chairman","email":"chairman@example.com","password":"Use-Another-Unique-Password"}
```

Use a REST client such as Postman or `curl`. The setup route refuses to create a second account for a role already provisioned. Once both accounts exist, rotate/delete the setup secret and redeploy. Never share account passwords.

## 3. Deploy the frontend to GitHub Pages

1. Create a new GitHub repository, e.g. `ecsa-e-voting`.
2. Upload `index.html`, `styles.css`, `app.js`, and `config.js` to the repository root.
3. Edit `config.js` and replace the placeholder with your deployed Worker URL.
4. In GitHub, open **Settings → Pages**.
5. Under Build and deployment, select **Deploy from a branch**, choose `main` and `/ (root)`, then Save.
6. If your site is a project page, set `ALLOWED_ORIGIN` to `https://YOUR-USERNAME.github.io` (origin only; no repository path). If using a custom domain, set that origin instead.
7. Visit the Pages URL after deployment.

## 4. Create an election

Sign in as President or Election Chairman. Use **Election settings** to create an election. Then create all elective positions under **Positions**. Register candidates under **Aspirants**. Candidate photograph (image, max 3 MB) and manifesto PDF (max 5 MB) are uploaded from the candidate list after registration.

The current API uses the first/active election. Create and configure the election before students register/vote. Candidate changes are blocked once voting starts. Candidate profile photos and PDFs are stored privately in R2 and served through API routes (photo delivery endpoint should be completed before production; see checklist).

## 5. Test before opening voting

- Register test students with unique 9-digit matric numbers and unique emails.
- Test duplicate matric and email rejection.
- Test wrong password and admin role access.
- Test 1–10 candidates per position; confirm the 11th is rejected.
- Test one vote per position using two browser sessions and repeated requests.
- Test results hidden, published and live modes.
- Test mobile layout.
- Back up D1 and R2 before the election.

## Security and operational notes

- Do not commit secrets, passwords, tokens, or `.dev.vars`.
- Configure Cloudflare rate limiting/WAF for login and registration endpoints.
- Enable Cloudflare account MFA.
- Use unique, long administrator passwords and rotate them if exposed.
- Add an independent election observer and publish election rules before voting.
- Do not expose individual voter choices. Do not edit or delete ballots manually.
- Keep a documented process for disputes, outages, recounts and data retention.
- Use HTTPS only.
