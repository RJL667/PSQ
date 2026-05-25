# Brand assets — Cyber Security Assessment deck

This folder holds the brand-facing assets and configuration that drive the
**Cyber Security Assessment** ("Executive Summary Deck") PDF output. The
generator (`pdf_report.py :: _build_assessment_pdf`) reads `brand.json` at
runtime and looks up the image files referenced inside it.

## Why this folder exists

The scanner is currently issued under **Phishield UMA (Pty) Ltd** (FSP 46418).
If the scanner moves into a separate commercial entity later — e.g. to avoid
conflicts with the underwriting arm — re-branding the deck is a config + asset
swap, not a code change.

## What to drop in

| File | Purpose | Recommended specs |
|---|---|---|
| `logo.png` | Corner wordmark/icon shown on every slide (top-right on the dark navy "Next Steps" slide; bottom-right on every other slide). | Transparent PNG. ~200 × 60 px (landscape mark+text) or ~60 × 60 px (icon only). The deck will scale it down to ~80 pt wide. |
| `cover_hero.jpg` | Slide 1 right-side hero image. Mirrors Kaizen's cyber-ops command-centre photo. | Landscape JPG. ~960 × 540 source. Will be placed in the right half of slide 1; the title sits on the left half. |
| `findings_hero.jpg` | Slide 6 right-side hero image. Mirrors Kaizen's office-workers-in-motion photo. | Portrait or square JPG. ~600 × 800 source. Will be placed in the right ~⅓ of slide 6. |

**All three are optional.** If a file is missing, the slide renders without the
image (title and content still appear). No errors, no broken layout — just less
visual richness.

## How to swap companies

Edit `brand.json` and replace the asset files. The deck will pick up the new
values on the next PDF render — no server restart needed for the JSON (it is
re-read on every PDF generation). The image files are only read once per
PDF — replacing them between renders is fine.

Fields in `brand.json`:

- `company_name` — short name (used in headings and CTAs, e.g. "Phishield broker").
- `legal_entity` — full legal name (used in disclosures).
- `regulatory_text` — FSP/regulatory line (currently hidden — `pdf_report.py`
  no longer prints a slide footer, but kept here for future use).
- `broker_label` — the noun used in the "contact your … broker" CTA on slide 7.
- `primary_navy_hex` / `accent_blue_hex` — brand colours. (For now only used
  if a future code change reads them; the current palette is hard-coded to
  navy/amber/red.)
- `logo_file` / `cover_hero_file` / `findings_hero_file` — image filenames
  *relative to this folder*. Change these if you prefer different filenames.
