# Safe-URL-Check
Phishing Url checker

## Environment variables and deployment

This project expects several API keys to be present as environment variables for threat
intelligence integrations. Do not commit your real `.env` file to source control.

1. Create a local `.env` for development:

	 - Copy the example: `cp .env.example .env` (or in PowerShell: `Copy-Item .env.example .env`).
	 - Fill in your API keys.

2. Load env variables in PowerShell for current session:

```powershell
$env:SAFE_BROWSING_API_KEY = 'your_key_here'
$env:OTX_API_KEY = 'your_key_here'
$env:URLHAUS_API_KEY = 'your_key_here'
```

For Windows CMD (current session):

```cmd
set SAFE_BROWSING_API_KEY=your_key_here
set OTX_API_KEY=your_key_here
set URLHAUS_API_KEY=your_key_here
```

3. Persisting env vars on Windows (PowerShell):

```powershell
setx SAFE_BROWSING_API_KEY "your_key_here"
setx OTX_API_KEY "your_key_here"
setx URLHAUS_API_KEY "your_key_here"
```

4. Deploying to Vercel:

- In the Vercel dashboard, go to your project > Settings > Environment Variables and add
	the variables (`SAFE_BROWSING_API_KEY`, `OTX_API_KEY`, `URLHAUS_API_KEY`) for the
	appropriate environment (Production/Preview/Development).
- Alternatively, use the Vercel CLI:

```powershell
vercel env add SAFE_BROWSING_API_KEY production
vercel env add OTX_API_KEY production
vercel env add URLHAUS_API_KEY production
```

Once variables are configured in Vercel, deployments will have access to them and
the health checks will report the services as available.

