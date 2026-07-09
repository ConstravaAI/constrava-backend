# Constrava

Constrava is an AI-assisted business command center for turning messy activity into structured records, priorities, analytics, and next actions.

## Run locally

```powershell
cd C:\Users\jerne\Documents\Codex\2026-07-09\ca\constrava-backend
$env:OPENAI_API_KEY="your_key_here"
node src/server.js
```

Then open `http://localhost:3000`.

The app runs without an OpenAI key using a deterministic local planner. When `OPENAI_API_KEY` is set, `/api/records/plan`, `/api/search/natural`, and `/api/reports/generate` use OpenAI structured JSON responses and fall back safely if the provider is unavailable.

## Important routes

- `POST /api/records/plan` turns raw notes, form submissions, uploads, or emails into a validated action plan.
- `POST /api/records/commit` writes an accepted plan as connected records.
- `GET /api/records` lists searchable and sortable records.
- `PATCH /api/records/:id` updates a record manually.
- `POST /api/sources/form` receives website form submissions and plans records from them.
- `POST /api/uploads/import` imports CSV/text and returns AI plans.
- `POST /api/analytics/events` stores tracking events.
- `GET /api/dashboard/summary` returns dashboard metrics and recommended actions.
- `POST /api/search/natural` converts a plain-English search into safe filters.
- `POST /api/reports/generate` creates factual reports with AI interpretation.

## Current scope

This is a complete first build in one Node process with file-based persistence in `data/store.json`. The service boundaries are organized so the persistence layer can be replaced with Postgres/Neon later without rewriting the UI or API contract.
