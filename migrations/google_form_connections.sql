CREATE TABLE IF NOT EXISTS google_form_connections (
  id TEXT PRIMARY KEY,
  site_slug TEXT NOT NULL,
  form_slug TEXT NOT NULL,
  dashboard_token TEXT,
  google_account_email TEXT,
  google_form_id TEXT,
  google_form_name TEXT,
  access_token TEXT,
  refresh_token TEXT,
  expires_at BIGINT,
  scope TEXT,
  connected_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_google_form_connections_dashboard_token
  ON google_form_connections (dashboard_token);

CREATE INDEX IF NOT EXISTS idx_google_form_connections_site_slug
  ON google_form_connections (site_slug);
