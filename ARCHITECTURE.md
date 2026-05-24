# PhishGuard AI — Architecture & Design

## Overview

PhishGuard AI is a **semi-adaptive phishing detection system** that combines static heuristics, machine learning, and human-in-the-loop feedback to improve URL threat detection over time.

It is **not** an autonomous cybersecurity AI. It requires deliberate human review and periodic retraining.

---

## System Components

### 1. Real-Time Prediction Engine

**File:** `app/analysis_engine.py`

**Purpose:** Analyze a URL and return a threat prediction immediately.

**How it works:**
- Extracts 40 rich features from the URL:
  - Syntactic patterns (length, dots, hyphens, special characters)
  - Domain properties (age, entropy, reputation)
  - Security signals (HTTPS, IP-based domains, shorteners)
  - Behavioral patterns (redirects, suspicious keywords, subdomain abuse)
  - Brand abuse detection (impersonation of PayPal, Google, etc.)
- Combines signals with ML model prediction:
  - ML model contribution: 40 points (scaled phishing probability)
  - Heuristic contributions: 60 points (domain age, entropy, impersonation, TLD, etc.)
  - Trusted domain reduction: -50 points (Google, GitHub, etc.)
- Returns:
  - `prediction` (SAFE / SUSPICIOUS / PHISHING)
  - `risk_score` (0–100)
  - `reasons` (explanation list)
  - `safety_tips` (guidance for phishing URLs)

**Limitation:** Uses a model trained on historical data. Cannot adapt in real-time.

---

### 2. User Feedback Collection

**File:** `run.py` (`/feedback` route)

**Purpose:** Collect correction data from users who know a prediction was wrong.

**How it works:**
- User clicks "Correct" or "Incorrect" after seeing a prediction.
- System records:
  - URL
  - predicted label (PHISHING / LEGITIMATE / SAFE)
  - corrected label (inferred from button: if predicted=PHISHING and user says incorrect, corrected=LEGITIMATE)
  - risk score
  - user ID
  - timestamp

**Status:** `PENDING` by default — not automatically used for retraining.

**Limitation:** Feedback is raw user input. Users can be wrong. Attackers can poison feedback.

---

### 3. Admin Review Panel

**File:** `run.py` (`/admin/feedback` route), `templates/admin_feedback.html`

**Purpose:** Prevent poisoning. Ensure only validated corrections enter retraining.

**How it works:**
- Admin views all pending feedback.
- Reviews each URL and correction claim.
- Clicks "Approve" or "Reject" with optional notes.
- Only `APPROVED` feedback can be used by the retrainer.

**Status:** Mandatory gate before retraining.

**Limitation:** Admins are human. This requires domain expertise and effort.

---

### 4. Periodic Offline Retraining

**File:** `retrain_model.py`

**Purpose:** Improve the ML model using human-validated feedback.

**How it works:**
1. Loads original dataset (already feature-engineered).
2. Loads approved feedback rows from the database.
3. Merges and extracts 40-feature vectors for all URLs.
4. Splits 80% train / 20% test.
5. Trains a new RandomForest model.
6. Evaluates on held-out test set:
   - Precision (minimize false positives)
   - Recall (catch real phishing)
   - F1-score (harmonic mean)
   - False positive rate (critical for security)
7. Saves versioned model (`model_v1.pkl`, `model_v2.pkl`, etc.)
8. Writes metrics report (`model/model_metrics.json`)
9. Updates latest alias (`model/phishing_model.pkl`)

**Frequency:** Manual / scheduled (not automatic)

**Limitations:**
- Requires admin effort to review feedback first.
- Model training takes minutes (not real-time).
- New model may perform worse; requires careful evaluation before rollout.
- Cannot adapt to new phishing tactics faster than the feedback cycle.

---

### 5. Feature Engineering

**File:** `model/live_features.py`

**Current feature set (40 features):**

| Category | Features | Signal |
|----------|----------|--------|
| **URL Shape** | length, dots, hyphens, slashes, etc. | Random/obfuscated URLs are suspicious |
| **Domain** | domain age, entropy, reputation, TLD | New domains, random names, bad TLDs are risky |
| **Security** | HTTPS present, IP-based domain, shortener | Missing HTTPS, IP domains are red flags |
| **Brand** | impersonation detection, keyword matching | "paypal-login.xyz" is classic phishing |
| **Structure** | path depth, query count, subdomain abuse | Deep paths, suspicious subdomains signal phishing |
| **Redirect** | chain count | Multiple redirects can hide true destination |

**Why 40 instead of 14?** The original extractor was too thin. Strong features matter far more than algorithm choice.

---

### 6. QR Code Intake Boundary

**File:** `run.py` (`/analyze-qr` route)

**Purpose:** Decode a QR image into a URL and then run the exact same URL analysis pipeline used for direct link submissions.

**Trust boundary:**
- Only image uploads are accepted.
- Uploaded files are capped at 4 MB and validated as real images before decoding.
- QR metadata is ignored; only the decoded text payload is used.
- The decoded payload is treated as untrusted text until it passes the same URL normalization and validation checks as direct links.
- Oversized, malformed, or unreadable QR payloads are rejected before any analysis begins.

**Security note:** QR handling is a convenience input path, not a privileged data source. A QR image should never be trusted more than a pasted URL.

---

## What This System Actually Does

✅ **Can Do:**
- Detect obvious phishing patterns (misspelled brand names, suspicious TLDs).
- Leverage human expertise via feedback (admins know what's phishing).
- Improve incrementally as approved feedback accumulates.
- Provide explainable predictions (list 5+ reasons why a URL is flagged).
- Track model performance (precision, recall, FP rate).
- Rollback to older models if a new version degrades.
- Reduce false positives by training on validated corrections.

❌ **Cannot Do:**
- Adapt in real-time. Retraining is offline and manual.
- Detect zero-day phishing tactics not seen in training data.
- Guarantee no false positives. Trade-off is unavoidable in security.
- Work without human review. Feedback poisoning is a real risk.
- Scale autonomously. Admin review is a bottleneck.
- Replace a professional security team. This is one tool in a larger toolkit.

---

## ML Ops Practices Implemented

1. **Versioned Models**
   - Each retrain saves `model_vN.pkl`.
   - Latest alias (`phishing_model.pkl`) points to current production.
   - Rollback is possible.

2. **Held-Out Test Set**
   - Model never sees 20% of training data.
   - Metrics are honest, not overfitted.

3. **Cybersecurity-Focused Metrics**
   - Precision: How many flagged URLs are actually phishing?
   - Recall: How many real phishing URLs do we catch?
   - FP rate: How often do we incorrectly flag safe URLs?
   - Not accuracy: misleading in imbalanced datasets.

4. **Metrics Persistence**
   - Each retrain writes `model/model_metrics.json`.
   - Track performance trends over time.

5. **Feature Integrity**
   - Feature names stored with model or inferred from code.
   - New models handle feature schema changes gracefully.

6. **Audit Logging**
   - User actions logged to `audit_logs` table.
   - Admin reviews logged.
   - Feedback recorded with timestamps.

---

## Typical Workflow

### Day 1: Initial Deployment
- Use pre-trained model (`model/phishing_model.pkl`).
- Users scan URLs, get predictions.
- Some predictions are wrong (expected).
- Users submit feedback via "Correct / Incorrect" buttons.

### Week 1–2: Feedback Accumulation
- 50–100 URLs submitted as feedback.
- Admins review each one, validate, approve/reject.
- Approved: ~70–80% of submissions (rest are ambiguous or wrong).

### Week 2: Retraining
- Admin runs `python retrain_model.py`.
- 100 original + 60 approved feedback = 160 training rows.
- New model trained, metrics written.
- Admins check metrics: did precision improve? FP rate lower?
- If yes, deploy `model_v2.pkl` as latest.
- If no, stay with `model/model_v1.pkl`.

### Weeks 3+: Continuous Improvement
- Cycle repeats.
- Model slowly improves as feedback accumulates.
- Each retrain takes ~2–5 minutes.

---

## What Makes This "Real"

This is not a marketing demo. It is:

1. **Honest about limitations:**
   - Requires human review before retraining.
   - Cannot scale to millions of URLs without human overhead.
   - Focused on reducing false positives, not catching 100% of phishing.

2. **Production-grade:**
   - Versioned models (rollback possible).
   - Held-out test metrics (not overfitted).
   - Audit logs (accountability).
   - Admin review (safety gate).

3. **Explainable:**
   - Every prediction has 5+ reasons.
   - Features are interpretable (domain age, entropy, brand abuse).
   - No black-box nonsense.

4. **Incremental:**
   - Improves step-by-step.
   - Tracks progress via metrics.
   - Doesn't claim to be better than it is.

---

## What This Is NOT

❌ **Not an autonomous AI:**
- Requires human decision-making (admin review).
- Cannot learn without explicit feedback collection.
- Cannot deploy changes without human approval.

❌ **Not a magic solution:**
- Phishing evolves faster than retraining cycles.
- Determined attackers will find new tricks.
- This tool raises the bar, but doesn't eliminate risk.

❌ **Not a replacement for:**
- Email authentication (SPF, DKIM, DMARC).
- Browser security features.
- User education.
- Professional security teams.

---

## Future Improvements (For You)

If you extend this system:

1. **Active Learning:** Ask admins to label only the most uncertain predictions (not all feedback).
2. **Adversarial Testing:** Simulate attacker feedback to measure robustness.
3. **Real-Time Threat Intelligence:** Integrate known phishing lists (PhishTank, URLhaus).
4. **Browser Integration:** Warn users before they visit flagged URLs.
5. **Analytics Dashboard:** Show which phishing tactics are most common.
6. **A/B Testing:** Compare model versions on live traffic (with careful metrics).

---

## Summary

PhishGuard AI is a **semi-adaptive phishing detection system** optimized for incremental improvement, human review, and honest metrics. It is not an autonomous AI. It is a solid foundation for a practical security tool that respects its limitations while solving real problems.

