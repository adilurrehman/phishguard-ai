from app.analysis_engine import analyze_url


def predict_url(url):
    """Backward-compatible wrapper around centralized analyze_url()."""
    analysis = analyze_url(url)
    return analysis['prediction'], analysis['risk_score'], analysis['reasons']