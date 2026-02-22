# Vecta KMS Web Dashboard

React 18 + TypeScript + Tailwind UI for the Vecta KMS command center.

## Key Features

- Collapsible grouped sidebar with 22 tabs.
- Dynamic tab visibility from `public/config/deployment.yaml`.
- Login screen with Vecta branding and configurable admin credentials.
- Server-enforced forced password change on first login.
- Live WebSocket streams for alerts and audit events.

## Credential Configuration

Default admin credentials are configured in:

- `public/config/ui-auth.json`

Current defaults:

- Username: `admin`
- Password: `VectaAdmin@2026`

`force_password_change: true` requires password rotation right after first login.

## Run

```bash
npm install
npm run dev
```

Backend contract:

- `POST /auth/login` returns `access_token` and `must_change_password`.
- `POST /auth/change-password` rotates password and returns a new `access_token`.

Local fallback is disabled by default (`allow_local_fallback: false`).
