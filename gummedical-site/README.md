# Gum Medical — static React site (Cloudflare)

A React rebuild of [gummedical.com.au](https://gummedical.com.au) (currently
WordPress + Elementor), deployed as a single Cloudflare Worker that serves a
static, prerendered React app and handles the contact form / newsletter
signup via a small API.

This is a **fresh rebuild, not a pixel clone**: content, structure and branding
are carried over, but the layout is a clean, modern implementation using React
+ Tailwind CSS rather than reproducing Elementor's markup.

## How the site was built

Page copy, navigation structure, service listings, team roster, location
details, fees and news headlines were scraped from the live public site
(there was no WordPress export/admin access available) and hard-coded into
`src/data/*.ts`. A few things were **intentionally left as placeholders** and
need real content before this replaces the live site:

- **News article bodies** (`src/pages/NewsPost.tsx`) — only headlines were
  captured; the full article text needs to be copied in from WordPress.
- **Images** — no photos/logo were migrated. Add real assets under `public/`
  and reference them from the relevant pages/components.
- **Team member photos and individual bios** — the 18 practitioner pages
  reuse the short summary shown on the team roster page rather than each
  person's full individual bio (fetching all 18 original pages was out of
  scope for the initial scaffold).
- **Map embeds** — none were present/extracted from the original contact page.

## Architecture

- **Frontend**: Vite + React 18 + TypeScript + React Router + Tailwind CSS v4,
  built to static files in `dist/`.
- **Backend**: a single Cloudflare Worker (`worker/index.ts`) that:
  - Serves the built static assets (via the Workers `[assets]` binding, with
    `not_found_handling = "single-page-application"` so client-side routes
    like `/our-team/dr-amos-maina` resolve correctly).
  - Handles `POST /api/contact` and `POST /api/newsletter`, validating the
    submitted fields and sending an email via the [Resend](https://resend.com)
    API.

Both forms include a hidden honeypot field (`company`) — bots that fill in
every input get silently accepted without an email being sent.

## Local development

```bash
npm install
npm run dev          # Vite dev server for the React app (no /api routes)
```

To test the full thing (static assets + `/api/*` routes) together, build
first and run it through Wrangler:

```bash
cp .dev.vars.example .dev.vars   # then fill in a real RESEND_API_KEY
npm run build
npm run worker:dev    # wrangler dev — serves dist/ + the API on one origin
```

## Deployment (Cloudflare)

1. **Get a Resend account and API key** (or swap `sendViaResend` in
   `worker/index.ts` for whatever email API you'd rather use — Resend was
   picked for its simplicity, no AWS account required).
2. Set the secret (never commit it):
   ```bash
   npx wrangler secret put RESEND_API_KEY
   ```
3. Update the plain-text vars in `wrangler.toml` (`CONTACT_TO_EMAIL`,
   `CONTACT_FROM_EMAIL`, `NEWSLETTER_TO_EMAIL`) to the real destination/
   sending addresses. Note: the `CONTACT_FROM_EMAIL` domain must be a domain
   verified with Resend before it can send mail.
4. Add the `gummedical.com.au` zone to this Cloudflare account if it isn't
   already, then uncomment the `[[routes]]` block in `wrangler.toml`.
5. Deploy:
   ```bash
   npm run deploy   # builds the app, then `wrangler deploy`
   ```

## Project structure

```
gummedical-site/
├── src/
│   ├── data/          # scraped content: locations, team, services, news
│   ├── components/    # Header, Footer, Layout, ContactForm, NewsletterForm
│   ├── pages/          one component per route
│   └── App.tsx        # React Router route table
├── worker/index.ts    # Cloudflare Worker: static assets + /api/* handlers
├── wrangler.toml
└── .dev.vars.example  # copy to .dev.vars for local API testing
```
