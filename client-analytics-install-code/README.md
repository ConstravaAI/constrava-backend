# Client Analytics Install Code

This folder contains the first Constrava client-side analytics install block.

The goal is to make analytics setup simple for a client: they copy one small code block into their website, and Constrava can begin receiving useful website activity events.

## File

- `constrava-analytics-code-block.html` — the copy-paste snippet for a client website.

## Intended tracked activity

The snippet is designed to support tracking through `https://constravaai.com/tracker.js`:

- Page views
- Sessions
- Referrers
- UTM campaigns
- CTA and button clicks
- Link clicks
- Form submissions
- Scroll depth
- Device and browser context

## Install

Place the code once on every page, preferably right before the closing `</body>` tag.

```html
<script>
  window.ConstravaAnalytics = window.ConstravaAnalytics || {
    siteId: "CLIENT_SITE_ID",
    mode: "standard",
    trackPageViews: true,
    trackClicks: true,
    trackForms: true,
    trackScrollDepth: true,
    respectDoNotTrack: true
  };
</script>
<script async src="https://constravaai.com/tracker.js"></script>
```

Replace `CLIENT_SITE_ID` with the site ID generated inside the Constrava dashboard.

## Design direction

This should eventually become more than a basic analytics script. The long-term direction is a client-side intelligence layer that can connect website behavior to CRM records, lead quality, conversion funnels, and AI recommendations.
