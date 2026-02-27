# Deployment Guide

## Deploying to Vercel

### Option 1: Vercel CLI (Recommended)

1. Install Vercel CLI:
   ```bash
   npm i -g vercel
   ```

2. Login to Vercel:
   ```bash
   vercel login
   ```

3. Deploy:
   ```bash
   # Deploy to preview
   vercel

   # Deploy to production
   vercel --prod
   ```

### Option 2: Git Integration

1. Push this repo to GitHub
2. Import project in Vercel dashboard
3. Deploy automatically on every push

### Environment Variables

Set these in Vercel dashboard:

- `SAFE_BROWSING_API_KEY` - Google Safe Browsing API key
- `URLHAUS_API_KEY` - URLHaus API key (optional)
- `OTX_API_KEY` - AlienVault OTX API key (optional)

## Troubleshooting

### CSS not updating?
- Clear browser cache
- Check that CSS has `?v=2` query parameter
- Redeploy with `vercel --prod`

### API errors?
- Check environment variables are set
- Verify API keys are valid
- Check Vercel function logs
