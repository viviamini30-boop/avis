# Aivestora prototype

## Run the website and upload service locally

Requires Node.js 20.6 or later.

1. In the project folder, run `npm install`.
2. Run `node setup.js` once. It creates a private `.env` file with a random administrator password, encryption key, and session-signing secret. Save the displayed admin password somewhere secure. On an existing `.env`, setup only appends missing settings and preserves configured values.
3. Add your Twelve Data API key to `.env` as `TWELVE_DATA_API_KEY=your_key`. The key is used only by the local server and is never sent to the browser. Without a key, the dashboard shows an explicit unavailable message rather than invented chart data.
4. Run `npm start`, or use the VS Code task **Serve Aivestora.com Website**.
5. Open `http://127.0.0.1:3000/register.html` to create an account and submit the required details and identity documents. Successful registration signs the user in and opens the dashboard. Existing users can sign in at `http://127.0.0.1:3000/signin.html`. Review and download submitted documents at `http://127.0.0.1:3000/admin.html` with the separate password from setup.

Registration requires the full name, email, password (12–128 characters), phone, country or region, SSN, consent, and front and back of a driver's license. The password is stored as a salted scrypt hash, not in plaintext. Identity submission details and files are deleted after 30 days; user accounts remain until an administrator manually deletes them. Removing an expired or deleted identity submission does not remove its account. Documents may be JPEG, PNG, WebP, or PDF, up to 8 MB each. The server checks file signatures rather than trusting the browser-provided file type.

The dashboard starts with a $0.00 displayed balance and zero-valued metrics, without simulating returns. Administrators can add to or subtract from an individual account's displayed USD balance; updates are stored encrypted with the account and cannot reduce it below zero. This is a display-only value and does not transfer money. With a Twelve Data API key configured, signed-in users can view daily S&P 500, Nasdaq 100, and Dow Jones index charts and a descriptive 20-session momentum indicator. The server reads daily history and the latest quote over HTTPS, then streams provider quotes through an authenticated server-side WebSocket so the API key is never exposed to browsers. Market data is cached locally for five minutes; provider quotas and data delays may apply. Twelve Data's demo key is for limited sample symbols and does not enable live index coverage. If live market data is unavailable, the dashboard displays an explicitly labeled illustrative pattern and does not invent prices, returns, or signals. These informational indicators are not investment recommendations.

The administrator can change the admin password from the signed-in administrator workspace. The replacement must contain 12–128 printable English keyboard characters. It is encrypted in `private-uploads/admin-password.enc`, applies immediately, and remains active after server restarts. Keep the data-encryption key backed up; it is needed to decrypt this password and other private records.

## Sensitive data and deployment

Submission metadata (including SSNs), document contents, and user account records are encrypted with AES-256-GCM before they are written under `private-uploads/`. User passwords are separately protected by salted scrypt hashes. Signed-in sessions use an HttpOnly, SameSite=Strict cookie that expires after 12 hours. The dashboard is server-protected and requires a registered account. The administrator page requires a separate generated password to list, download, or delete submissions and to manually delete accounts. Expired submissions are removed on startup and hourly; account deletion is manual. Keep `.env` and `private-uploads/` out of source control and restrict access to both. Back up the encryption key and session secret securely: without them, encrypted data or existing sessions cannot be recovered.

The server binds to `127.0.0.1` by default and refuses to bind to a public interface. It is intended for local prototype use. **Do not collect real identity documents until it is deployed behind HTTPS, access controls and storage are reviewed, and appropriate privacy, consent, retention, and identity-verification requirements have been addressed.** For a trusted HTTPS reverse proxy on the same machine, configure `HOST=127.0.0.1`, `NODE_ENV=production`, and `TRUST_PROXY=loopback`. If the proxy connects from another IP, set `TRUST_PROXY` to that specific trusted proxy IP or CIDR only. The proxy must be the only network route to this service.

The service does not forward submissions by email or to a third party. An administrator must sign in to review and download them.

## Render deployment (staging only)

The repository includes a Render Blueprint in `render.yaml`. In Render, create a new Blueprint from `viviamini30-boop/avis` and select the `main` branch. The Blueprint uses Render's free web-service plan and does not provision persistent storage. It generates the administrator password, data-encryption key, and session secret as Render environment secrets.

The hosted service binds to `0.0.0.0` only when `NODE_ENV=production`, `ALLOW_PUBLIC_BIND=true`, and an explicit positive `TRUST_PROXY` hop count are all configured. The Blueprint trusts one Render proxy hop and uses temporary storage under `/tmp`. Do not change the proxy trust setting without verifying the hosting provider's proxy topology. Render's free web service spins down after idle periods, and files in its ephemeral filesystem can disappear on restarts, deploys, or spin-down.

**The Blueprint intentionally sets `ENABLE_IDENTITY_SUBMISSIONS=false`.** The public site can be deployed for staging, but registration and identity-document submissions return an unavailable response until this app's authentication, storage, backup and restore process, privacy controls, legal requirements, and operational access controls have been reviewed. Do not enable submissions or enter real personal data before that review. After review, an authorized operator can set `ENABLE_IDENTITY_SUBMISSIONS=true` in the Render service's environment and deploy the change.

This free deployment is only for a demo with no real user or personal data. Do not create accounts or change the admin password expecting those records to persist. Render free instances are not intended for production.

Never put secrets in the repository or in the Blueprint. Hosting a real-data production service requires a separately reviewed deployment with durable storage, backups, and appropriate privacy and access controls.
