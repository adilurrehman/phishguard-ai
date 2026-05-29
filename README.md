# PhishGuard AI

![Python](https://img.shields.io/badge/language-Python%203.11-blue.svg)
![Runtime](https://img.shields.io/badge/runtime-python--3.11.9-lightgrey.svg)
![License](https://img.shields.io/badge/license-Unspecified-lightgrey.svg)
![Build](https://img.shields.io/badge/build-manual-yellow.svg)

PhishGuard AI is an open, production-focused phishing detection tool that combines feature-rich URL analysis, machine learning predictions, and human‑in‑the‑loop feedback to help users and teams detect suspicious and phishing links quickly and explainably.

---

## Project Overview

PhishGuard AI analyzes submitted URLs and QR code payloads to return a clear prediction (SAFE / SUSPICIOUS / PHISHING) along with a numeric risk score, explanations, and safety tips. It matters because it combines automated detection with admin-reviewed feedback and versioned retraining so teams can safely iterate on model quality while limiting false positives.

Key metadata:

- **Language:** Python 3.11
- **Web:** Flask + Gunicorn
- **Model:** Versioned sklearn RandomForest (local `ml_model/`)
- **Database:** PostgreSQL (configurable via `DATABASE_URL`)

---

## AI Features ✨

- 🔍 **URL Risk Scoring** — Extracts ~40 features (URL shape, domain age, entropy, TLD signals, path depth, redirects) and produces a calibrated risk score (0–100).
- 🧠 **ML Prediction** — RandomForest-based model provides a probabilistic phishing score which is combined with heuristics for robust decisioning.
- 🧾 **Explainability** — Returns human-readable `reasons` that explain why a URL was flagged (e.g., brand-impersonation, suspicious TLD, high entropy).
- 🔁 **Human-in-the-loop Feedback** — Users can mark predictions as correct/incorrect; feedback is stored as `PENDING` until admin review before being used for retraining.
- 📦 **Versioned Models & Metrics** — Retrainer saves `model_vN.pkl`, writes `model_metrics.json`, and maintains a `phishing_model.pkl` alias for production.
- 📊 **Dashboard + History** — Per-user scan history and a dashboard summarizing counts, average risk, and recent scans.
- 📱 **QR Code Intake** — Secure QR image decoding that extracts and analyzes a single HTTP/HTTPS URL payload.

---

## Security Features 🔐

This project is built with layered defenses and safe defaults:

| Area | Implementations |
|------|-----------------|
| Authentication | Passwords hashed with `bcrypt`; session-based login (`/login`, `/signup`). |
| Authorization | `login_required` and `admin_required` decorators protect routes and admin actions. |
| Input Validation | Strict URL normalization + `validators` check; rejects local IPs/loopback/embedded credentials. |
| CSRF Protection | Per-session CSRF tokens enforced for state-changing POSTs. |
| Rate Limiting | Basic in-process rate limiting (request buckets) to reduce abuse. |
| Upload Hardening | QR uploads: MIME/type checks, file size limit (4 MB), max image pixels, animated image rejection. |
| HTTP Security Headers | `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. |
| Audit & Governance | `audit_logs` table records key actions (login attempts, feedback reviews, scans). |
| Data Protection | DB credentials via `DATABASE_URL`; session cookies default to `HttpOnly` and `SameSite=Lax` (optionally `Secure`). |

Critical note: the repo currently does not embed a license file — add an appropriate `LICENSE` file before redistribution.

---

## Quick Start — Run Locally (30s)

1. Clone the repo and create a virtual environment

```bash
git clone https://github.com/adilurrehman/phishguard-ai.git
cd phishguard-ai
python -m venv venv
source venv/bin/activate   # macOS / Linux
# venv\Scripts\activate   # Windows (PowerShell)
```

2. Install dependencies

```bash
pip install -r requirements.txt
```

3. Configure environment variables (example `.env`)

```env
SECRET_KEY=replace-with-a-secure-secret
DATABASE_URL=postgres://user:pass@localhost:5432/phishguard
PHISHGUARD_SECURE_COOKIES=0   # 1 if running behind HTTPS
```

4. Start the app (development)

```bash
python run.py
# or with gunicorn for production-like behavior:
gunicorn run:app
```

5. Visit http://127.0.0.1:5000 and create an account via `/signup`.

---

## Developer Details 🛠️

Project layout (high level):

```
run.py                 # Flask app & routes
app/analysis_engine.py # Core URL feature extraction + join with ML model
app/auth.py            # password hashing & verification
app/security.py        # login_required / admin_required
app/db.py              # DB connection + schema ensure
model/                 # training utilities + metrics
ml_model/              # trained model artifacts (large files)
templates/, static/    # UI
```

Setup and development

1. Ensure `DATABASE_URL` points to a Postgres instance and run `test_db.py`:

```bash
python test_db.py
# should print: Database Connected Successfully!
```

2. Run unit/quick tests for URL predictions:

```bash
python test_urls.py
```

3. Retrain model (manual operation):

```bash
python retrain_model.py
# outputs model/model_metrics.json and versioned model files
```

Dependencies and versions are listed in `requirements.txt`.

Contributing

- Fork the repo, create a feature branch, open a PR against `main`.
- Run linters/tests before PR. Keep commits focused and significant.
- For model/data changes, include evaluation results (`model_metrics.json`) and rationale in PR description.

---

## API & Key Endpoints 📚

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET/POST | `/analyze-link` | Login required | Submit a direct URL for analysis. |
| GET/POST | `/analyze-qr` | Login required | Upload a QR image; extracts and analyzes single http(s) URL. |
| POST | `/feedback` | Login required | Submit feedback on a prediction (correct/incorrect). |
| GET/POST | `/admin/feedback` | Admin only | Review and approve/reject user feedback. |
| GET | `/history` | Login required | View user's scan history. |
| GET | `/dashboard` | Login required | User statistics and recent scans. |

Authentication routes: `/signup`, `/login`, `/logout`.

---

## Configuration Options

| Env Var | Purpose | Default |
|---------|---------|---------|
| `SECRET_KEY` | Flask secret for sessions | (required) |
| `DATABASE_URL` | Postgres connection string | (required) |
| `PHISHGUARD_SECURE_COOKIES` | Enable secure cookie flag (1 = True) | `0` |

Other runtime limits are defined in `run.py` (QR limits, max URL length, image pixel limits).

---

## Troubleshooting & Common Issues

- Push failing due to model size: `ml_model/phishing_model.pkl` may exceed GitHub limits — use Git LFS:

```bash
git lfs install
git lfs track "ml_model/*.pkl"
git add .gitattributes
git add ml_model/*.pkl
git commit -m "Move models to LFS"
git push
```

- Database connection errors: verify `DATABASE_URL` and that Postgres is reachable.
- QR decode failing: check image format (PNG/JPEG/WEBP/BMP) and size (< 4 MB). Ensure QR contains only a single HTTP/HTTPS URL.

---

## Performance Considerations ⚡

- Feature extraction and model inference are fast for single requests, but retraining is offline and can take several minutes — schedule retraining during maintenance windows.
- For scale, consider:
	- Caching repeated domain reputation lookups
	- Offloading model inference to a lightweight API (separate worker) or using a model server
	- Moving rate limiting and session storage out of process to Redis

---

## Roadmap

- [ ] Add CI (GitHub Actions) for tests and linting
- [ ] Move large models to Git LFS and publish model artifact releases
- [ ] Add an optional REST API with token auth for programmatic use
- [ ] Improve automated retraining pipeline with canary rollout for models

---

## Credits & Acknowledgments

- Creator: Adil ur Rehman Kakar — developer profile available at `/developer` in the app.
- Built with: Flask, scikit-learn, OpenCV, Pillow, PostgreSQL.

---

If you want, I can also add a LICENSE (MIT/Apache-2.0) and wire Git LFS handling for the `ml_model/` directory. Open an issue or reply here with your preference.

