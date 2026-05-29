from io import BytesIO
from pathlib import Path
import ipaddress
import os
import re
import secrets
import time
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

from flask import Flask, request, render_template, redirect, session, make_response, jsonify
from PIL import Image, UnidentifiedImageError
from PIL.Image import DecompressionBombError
import cv2
import numpy as np
import validators
from datetime import datetime, timedelta
from app.analysis_engine import analyze_url
from app.db import get_db_connection
from app.auth import hash_password, verify_password
from app.security import login_required, admin_required

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")

DATABASE_URL = os.getenv("DATABASE_URL")

app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

Image.MAX_IMAGE_PIXELS = 4_000_000

ALLOWED_QR_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.webp', '.bmp'}
ALLOWED_QR_MIME_TYPES = {'image/png', 'image/jpeg', 'image/webp', 'image/bmp'}
ALLOWED_QR_PIL_FORMATS = {'PNG', 'JPEG', 'WEBP', 'BMP'}

MAX_ANALYSIS_URL_LENGTH = 2048
MAX_QR_DIMENSION = 2048
MAX_QR_PAYLOAD_LENGTH = 4096

HTTP_URL_REGEX = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
WWW_URL_REGEX = re.compile(r"\bwww\.[^\s<>\"')]+", re.IGNORECASE)


class CsrfError(ValueError):
    pass


class RateLimitError(ValueError):
    pass


CSRF_SESSION_KEY = '_csrf_token'
RATE_LIMIT_WINDOW_SECONDS = 5 * 60
RATE_LIMIT_MAX_REQUESTS = 30
_RATE_LIMIT_STATE = {}


def _get_client_ip():

    forwarded_for = request.headers.get('X-Forwarded-For', '')

    if forwarded_for:
        return forwarded_for.split(',')[0].strip()

    return request.remote_addr or 'unknown'


def _enforce_rate_limit(bucket):

    key = f"{bucket}:{_get_client_ip()}"
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS

    timestamps = _RATE_LIMIT_STATE.get(key, [])
    timestamps = [t for t in timestamps if t >= window_start]

    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        raise RateLimitError('Too many requests. Please wait and try again.')

    timestamps.append(now)
    _RATE_LIMIT_STATE[key] = timestamps


def _get_csrf_token():

    token = session.get(CSRF_SESSION_KEY)

    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token

    return token


def _require_csrf_token():

    token = (request.form.get('csrf_token', '') or '').strip()
    expected = session.get(CSRF_SESSION_KEY, '')

    if not token or not expected or not secrets.compare_digest(token, expected):
        raise CsrfError('Invalid request token. Please refresh the page and try again.')


@app.context_processor
def inject_csrf_token():

    return {'csrf_token': _get_csrf_token()}


def _extract_http_urls(text):

    if not text:
        return []

    urls = HTTP_URL_REGEX.findall(text)

    if urls:
        return urls

    www_hits = WWW_URL_REGEX.findall(text)

    return [f"https://{hit}" for hit in www_hits]


def _extract_single_http_url(text):

    urls = _extract_http_urls(text)

    if not urls:
        return None

    if len(urls) > 1:
        raise ValueError('Multiple URLs detected in QR code payload')

    return urls[0]


# SESSION SECURITY SETTINGS
app.config['SESSION_PERMANENT'] = False

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

app.config['SESSION_COOKIE_HTTPONLY'] = True

app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Set to 1 when running behind HTTPS.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('PHISHGUARD_SECURE_COOKIES', '0') == '1'


def wants_json_response():

    return request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.best == 'application/json'


def _normalize_and_validate_url(raw_url):

    cleaned_url = (raw_url or '').strip()

    if not cleaned_url:
        raise ValueError('URL cannot be empty')

    if len(cleaned_url) > MAX_ANALYSIS_URL_LENGTH:
        raise ValueError('URL is too long')

    if any(ord(character) < 32 for character in cleaned_url):
        raise ValueError('URL contains invalid characters')

    if not validators.url(cleaned_url):
        raise ValueError('Invalid URL format')

    parsed_url = urlparse(cleaned_url)

    if parsed_url.scheme not in {'http', 'https'}:
        raise ValueError('Only http and https URLs are allowed')

    if not parsed_url.netloc:
        raise ValueError('Invalid URL format')

    if parsed_url.username or parsed_url.password:
        raise ValueError('URLs with embedded credentials are not allowed')

    hostname = (parsed_url.hostname or '').strip().lower()

    if not hostname:
        raise ValueError('Invalid URL format')

    if hostname in {'localhost'} or hostname.endswith('.local'):
        raise ValueError('Local network URLs are not allowed')

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        # hostname is not a literal IP address
        pass
    else:
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise ValueError('Local network URLs are not allowed')

    return cleaned_url


def _decode_qr_image(uploaded_file):

    if uploaded_file is None or not uploaded_file.filename:
        raise ValueError('Please upload a QR image')

    if not uploaded_file.mimetype:
        raise ValueError('Unsupported QR image type')

    file_suffix = Path(uploaded_file.filename).suffix.lower()

    if file_suffix not in ALLOWED_QR_EXTENSIONS:
        raise ValueError('Unsupported QR image format')

    if uploaded_file.mimetype not in ALLOWED_QR_MIME_TYPES:
        raise ValueError('Unsupported QR image type')

    file_bytes = uploaded_file.read()

    if not file_bytes:
        raise ValueError('Uploaded QR image is empty')

    if len(file_bytes) > app.config['MAX_CONTENT_LENGTH']:
        raise ValueError('Uploaded QR image is too large')

    try:
        with Image.open(BytesIO(file_bytes)) as probe:
            probe.verify()

        with Image.open(BytesIO(file_bytes)) as image:
            if image.format and image.format.upper() not in ALLOWED_QR_PIL_FORMATS:
                raise ValueError('Unsupported QR image type')

            if getattr(image, 'is_animated', False) or getattr(image, 'n_frames', 1) != 1:
                raise ValueError('Animated images are not allowed')

            image = image.convert('RGB')

            if image.width > MAX_QR_DIMENSION or image.height > MAX_QR_DIMENSION:
                raise ValueError('Uploaded QR image dimensions are too large')

            rgb = np.array(image)

    except DecompressionBombError as exc:
        raise ValueError('The uploaded image is too complex to process safely') from exc
    except UnidentifiedImageError as exc:
        raise ValueError('The uploaded file is not a valid image') from exc
    except OSError as exc:
        raise ValueError('The uploaded image could not be processed') from exc

    def _decode_payload(payload):
        payload = (payload or '').strip()

        if not payload:
            return None

        if len(payload) > MAX_QR_PAYLOAD_LENGTH:
            raise ValueError('QR code payload is too large')

        url = _extract_single_http_url(payload)

        if not url:
            raise ValueError('QR code does not contain an http(s) URL')

        return url

    try:
        detector = cv2.QRCodeDetector()

        bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
        gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        inverted = cv2.bitwise_not(thresh)

        for frame in (bgr, gray, thresh, inverted):
            qr_data, _, _ = detector.detectAndDecode(frame)
            if qr_data:
                return _decode_payload(qr_data)

        try:
            ok, decoded_info, _, _ = detector.detectAndDecodeMulti(bgr)
            if ok and decoded_info:
                for info in decoded_info:
                    if info:
                        return _decode_payload(info)
        except Exception:
            pass

        raise ValueError('No QR code could be decoded from the uploaded image')

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError('QR code detection failed. Please ensure the image contains a valid QR code.') from exc


def _store_analysis_result(url, audit_action):

    analysis = analyze_url(url)

    user_id = session['user_id']

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO scanned_urls
        (user_id, url, prediction, risk_score)
        VALUES (%s, %s, %s, %s)
        """,
        (
            user_id,
            url,
            analysis['prediction'],
            analysis['risk_score'],
        )
    )

    cur.execute(
        """
        INSERT INTO audit_logs (action)
        VALUES (%s)
        """,
        (audit_action,)
    )

    conn.commit()

    cur.close()
    conn.close()

    return {
        'url': url,
        'prediction': analysis['prediction'],
        'risk_score': analysis['risk_score'],
        'reasons': analysis['reasons'],
        'safety_tips': analysis['safety_tips'],
    }


def _render_analysis_page(template_name, result=None, error=None, status_code=200):

    if wants_json_response():

        if error:
            return jsonify({'error': error}), status_code

        return jsonify({'result_html': render_template('_analysis_result.html', result=result)})

    return render_template(template_name, result=result, error=error), status_code


@app.before_request
def session_management():

    session.permanent = True

    if 'user_id' in session:

        now = datetime.now()

        if 'last_activity' in session:

            last_activity = datetime.fromisoformat(
                session['last_activity']
            )

            inactivity = now - last_activity

            if inactivity > timedelta(minutes=15):

                session.clear()

                return redirect('/login')

        session['last_activity'] = now.isoformat()


@app.after_request
def apply_security_headers(response):

    response.headers['X-Content-Type-Options'] = 'nosniff'

    response.headers['X-Frame-Options'] = 'DENY'

    response.headers['Referrer-Policy'] = 'no-referrer'

    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    response.headers['Content-Security-Policy'] = (
        "default-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )

    response.headers['Cache-Control'] = 'no-store'

    return response


@app.errorhandler(413)
def request_entity_too_large(error):

    message = 'The uploaded file is too large. Please use a file under 4 MB.'

    if wants_json_response():
        return jsonify({'error': message}), 413

    if request.path.startswith('/analyze-qr'):
        template_name = 'analyze_qr.html'
    elif request.path.startswith('/analyze-link'):
        template_name = 'analyze_link.html'
    else:
        template_name = 'index.html'

    return render_template(template_name, error=message), 413


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/feedback', methods=['POST'])
@login_required
def feedback():

    try:
        _require_csrf_token()
    except CsrfError as exc:
        if wants_json_response():
            return jsonify({'error': str(exc)}), 403
        return make_response(str(exc), 403)

    url = _normalize_and_validate_url(request.form.get('url', ''))
    predicted_label = request.form.get('predicted_label', '').strip()
    risk_score = request.form.get('risk_score', '').strip()
    feedback_value = request.form.get('feedback', '').strip()

    # DETERMINE TRUE LABEL
    if feedback_value == 'correct':

        correct_label = predicted_label

    else:

        if predicted_label == 'PHISHING':
            correct_label = 'LEGITIMATE'

        else:
            correct_label = 'PHISHING'

    user_id = session['user_id']

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO feedback
        (
            user_id,
            url,
            predicted_label,
            correct_label,
            risk_score,
            feedback,
            review_status
        )
        VALUES (%s, %s, %s, %s, %s, %s, 'PENDING')
        """,
        (
            user_id,
            url,
            predicted_label,
            correct_label,
            risk_score,
            feedback_value,
        )
    )

    cur.execute(
        """
        INSERT INTO audit_logs (action)
        VALUES (%s)
        """,
        (f"Feedback submitted for URL: {url} ({feedback_value})",)
    )

    conn.commit()

    cur.close()
    conn.close()

    if wants_json_response():
        return jsonify({"status": "ok", "message": "Thank you for your feedback!"})

    return redirect('/')


@app.route('/admin/feedback', methods=['GET', 'POST'])
@admin_required
def admin_feedback():

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':

        try:
            _require_csrf_token()
        except CsrfError as exc:
            cur.close()
            conn.close()
            return make_response(str(exc), 403)

        feedback_id = request.form.get('feedback_id', '').strip()
        action = request.form.get('action', '').strip().upper()
        review_notes = request.form.get('review_notes', '').strip()

        if feedback_id.isdigit() and action in {'APPROVED', 'REJECTED'}:

            cur.execute(
                """
                UPDATE feedback
                SET review_status = %s,
                    reviewed_by = %s,
                    reviewed_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (
                    action,
                    session['user_id'],
                    int(feedback_id),
                )
            )

            cur.execute(
                """
                INSERT INTO audit_logs (action)
                VALUES (%s)
                """,
                (f"Feedback {action.lower()} by admin for id={feedback_id}: {review_notes}",)
            )

            conn.commit()

    cur.execute(
        """
        SELECT
            f.id,
            u.username,
            f.url,
            f.predicted_label,
            f.correct_label,
            f.risk_score,
            f.feedback,
            f.review_status,
            f.created_at,
            f.reviewed_at
        FROM feedback f
        LEFT JOIN users u ON f.user_id = u.id
        ORDER BY f.created_at DESC
        """
    )

    feedback_rows = cur.fetchall()

    pending_count = sum(1 for row in feedback_rows if row[7] == 'PENDING')

    cur.close()
    conn.close()

    return render_template(
        'admin_feedback.html',
        feedback_rows=feedback_rows,
        pending_count=pending_count,
    )

@app.route('/', methods=['GET'])
@app.route('/menu', methods=['GET'])
@login_required
def home():

    return render_template('index.html')


@app.route('/analyze-link', methods=['GET', 'POST'])
@login_required
def analyze_link():

    result = None
    error = None
    status_code = 200

    if request.method == 'POST':

        try:
            _require_csrf_token()
            _enforce_rate_limit('analyze-link')

            url = _normalize_and_validate_url(request.form.get('url', ''))
            result = _store_analysis_result(url, f'URL scanned from link workflow: {url}')
            result['analysis_source'] = 'Direct link'
        except RateLimitError as exc:
            error = str(exc)
            status_code = 429
        except CsrfError as exc:
            error = str(exc)
            status_code = 403
        except ValueError as exc:
            error = str(exc)
            status_code = 400

        if error:
            return _render_analysis_page('analyze_link.html', result=None, error=error, status_code=status_code)

        if wants_json_response():
            return jsonify({'result_html': render_template('_analysis_result.html', result=result)})

    return render_template('analyze_link.html', result=result, error=error)


@app.route('/analyze-qr', methods=['GET', 'POST'])
@login_required
def analyze_qr():

    result = None
    error = None
    status_code = 200

    if request.method == 'POST':

        try:
            _require_csrf_token()
            _enforce_rate_limit('analyze-qr')

            uploaded_files = request.files.getlist('qr_image')

            if len(uploaded_files) != 1:
                raise ValueError('Please upload exactly one QR image')

            decoded_url = _decode_qr_image(uploaded_files[0])
            url = _normalize_and_validate_url(decoded_url)
            result = _store_analysis_result(url, f'QR code analyzed: {url}')
            result['analysis_source'] = 'QR code'
            result['extracted_url'] = url
        except RateLimitError as exc:
            error = str(exc)
            status_code = 429
        except CsrfError as exc:
            error = str(exc)
            status_code = 403
        except ValueError as exc:
            error = str(exc)
            status_code = 400

        if error:
            return _render_analysis_page('analyze_qr.html', result=None, error=error, status_code=status_code)

        if wants_json_response():
            return jsonify({'result_html': render_template('_analysis_result.html', result=result)})

    return render_template('analyze_qr.html', result=result, error=error)

@app.route('/history')
@login_required
def history():

    user_id = session['user_id']
    search = request.args.get('search', '')

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            url,
            prediction,
            risk_score,
            scanned_at
        FROM scanned_urls
        WHERE user_id = %s
        AND url ILIKE %s
        ORDER BY scanned_at DESC
        """,
        (
            user_id,
            f'%{search}%'
        )
    )

    scans = cur.fetchall()

    cur.execute(
        """
        SELECT COUNT(*)
        FROM scanned_urls
        WHERE user_id = %s
        AND url ILIKE %s
        """,
        (
            user_id,
            f'%{search}%'
        )
    )

    total_scans = cur.fetchone()[0]

    cur.execute(
        """
        SELECT COUNT(*)
        FROM scanned_urls
        WHERE user_id = %s
        AND prediction = 'PHISHING'
        AND url ILIKE %s
        """,
        (
            user_id,
            f'%{search}%'
        )
    )

    phishing_count = cur.fetchone()[0]

    cur.execute(
        """
        SELECT COUNT(*)
        FROM scanned_urls
        WHERE user_id = %s
        AND prediction = 'SUSPICIOUS'
        AND url ILIKE %s
        """,
        (
            user_id,
            f'%{search}%'
        )
    )

    suspicious_count = cur.fetchone()[0]

    cur.execute(
        """
        SELECT COUNT(*)
        FROM scanned_urls
        WHERE user_id = %s
        AND prediction = 'LEGITIMATE'
        AND url ILIKE %s
        """,
        (
            user_id,
            f'%{search}%'
        )
    )

    safe_count = cur.fetchone()[0]

    cur.close()
    conn.close()

    return render_template(
        'history.html',
        scans=scans,
        total_scans=total_scans,
        phishing_count=phishing_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count
    )



@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/developer')
@login_required
def developer():
    developer_profile = {
        'name': 'Adil ur Rehman Kakar',
        'role': 'Full Stack Web Developer',
        'headline': 'Creator of PhishGuard AI',
        'education': 'Student at UET, Lahore, Pakistan',
        'bio': (
            'Passionate about building innovative web solutions that solve real-world problems. '
            'I specialize in creating modern, responsive, and user-friendly web applications '
            'using practical technology choices and clean product thinking.'
        ),
        'avatar_url': '/static/images/adil-avatar.webp',
        'stats': [
            {'value': '10+', 'label': 'Projects completed'},
            {'value': '2+', 'label': 'Years experience'},
            {'value': '100%', 'label': 'Client satisfaction'},
        ],
        'skills': [
            'Python',
            'Flask',
            'JavaScript',
            'Bootstrap',
            'HTML5',
            'CSS3',
            'React',
            'Node.js',
            'Git',
            'MongoDB',
        ],
        'links': [
            {'label': 'Email', 'href': 'mailto:adilurrehmanofficial@gmail.com', 'icon': 'bi-envelope-fill', 'variant': 'email'},
            {'label': 'LinkedIn', 'href': 'https://linkedin.com/in/adilurrehmanofficial', 'icon': 'bi-linkedin', 'variant': 'linkedin'},
            {'label': 'Instagram', 'href': 'https://instagram.com/adilurrehmanofficial', 'icon': 'bi-instagram', 'variant': 'instagram'},
            {'label': 'GitHub', 'href': 'https://github.com/adilurrehman', 'icon': 'bi-github', 'variant': 'github'},
        ],
        'highlights': [
            {
                'title': 'Security-first thinking',
                'text': 'Builds products that protect users and surface risks clearly, which matches the goal behind PhishGuard AI.'
            },
            {
                'title': 'Full-stack execution',
                'text': 'Comfortable moving from interface design to backend logic and practical delivery.'
            },
            {
                'title': 'User-centered UI',
                'text': 'Focuses on making the experience understandable, responsive, and easy to trust.'
            },
        ],
    }

    return render_template('developer.html', developer=developer_profile)


@app.route('/developer/data')
@login_required
def developer_data():
    developer_profile = {
        'name': 'Adil ur Rehman Kakar',
        'role': 'Full Stack Web Developer',
        'headline': 'Creator of PhishGuard AI',
        'education': 'Student at UET, Lahore, Pakistan',
        'bio': (
            'Passionate about building innovative web solutions that solve real-world problems. '
            'I specialize in creating modern, responsive, and user-friendly web applications '
            'using practical technology choices and clean product thinking.'
        ),
        'avatar_url': '/static/images/adil-avatar.webp',
        'stats': [
            {'value': '10+', 'label': 'Projects completed'},
            {'value': '2+', 'label': 'Years experience'},
            {'value': '100%', 'label': 'Client satisfaction'},
        ],
        'skills': [
            'Python',
            'Flask',
            'JavaScript',
            'Bootstrap',
            'HTML5',
            'CSS3',
            'React',
            'Node.js',
            'Git',
            'MongoDB',
        ],
        'links': [
            {'label': 'Email', 'href': 'mailto:adilurrehmanofficial@gmail.com', 'icon': 'bi-envelope-fill', 'variant': 'email'},
            {'label': 'LinkedIn', 'href': 'https://linkedin.com/in/adilurrehmanofficial', 'icon': 'bi-linkedin', 'variant': 'linkedin'},
            {'label': 'Instagram', 'href': 'https://instagram.com/adilurrehmanofficial', 'icon': 'bi-instagram', 'variant': 'instagram'},
            {'label': 'GitHub', 'href': 'https://github.com/adilurrehman', 'icon': 'bi-github', 'variant': 'github'},
        ],
        'highlights': [
            {
                'title': 'Security-first thinking',
                'text': 'Builds products that protect users and surface risks clearly, which matches the goal behind PhishGuard AI.'
            },
            {
                'title': 'Full-stack execution',
                'text': 'Comfortable moving from interface design to backend logic and practical delivery.'
            },
            {
                'title': 'User-centered UI',
                'text': 'Focuses on making the experience understandable, responsive, and easy to trust.'
            },
        ],
    }

    return jsonify({'content_html': render_template('_developer_content.html', developer=developer_profile)})

@app.route('/dashboard')
@login_required
def dashboard():

    user_id = session['user_id']

    conn = get_db_connection()
    cur = conn.cursor()

    # TOTAL SCANS
    cur.execute(
        """
        SELECT COUNT(*)
        FROM scanned_urls
        WHERE user_id = %s
        """,
        (user_id,)
    )

    total_scans = cur.fetchone()[0]

    # PHISHING COUNT
    cur.execute(
        """
        SELECT COUNT(*)
        FROM scanned_urls
        WHERE user_id = %s
        AND prediction = 'PHISHING'
        """,
        (user_id,)
    )

    phishing_count = cur.fetchone()[0]

    # SUSPICIOUS COUNT
    cur.execute(
        """
        SELECT COUNT(*)
        FROM scanned_urls
        WHERE user_id = %s
        AND prediction = 'SUSPICIOUS'
        """,
        (user_id,)
    )

    suspicious_count = cur.fetchone()[0]

    # SAFE COUNT
    cur.execute(
        """
        SELECT COUNT(*)
        FROM scanned_urls
        WHERE user_id = %s
        AND prediction = 'LEGITIMATE'
        """,
        (user_id,)
    )

    safe_count = cur.fetchone()[0]

    # AVERAGE RISK
    cur.execute(
        """
        SELECT AVG(risk_score)
        FROM scanned_urls
        WHERE user_id = %s
        """,
        (user_id,)
    )

    average_risk = cur.fetchone()[0]

    if average_risk is None:
        average_risk = 0

    # THREAT LEVEL CLASSIFICATION
    if average_risk < 30:
        threat_level = "SAFE"
    elif average_risk < 60:
        threat_level = "SUSPICIOUS"
    else:
        threat_level = "PHISHING"

    # RECENT SCANS
    cur.execute(
        """
        SELECT
            url,
            prediction,
            risk_score,
            scanned_at
        FROM scanned_urls
        WHERE user_id = %s
        ORDER BY scanned_at DESC
        LIMIT 5
        """,
        (user_id,)
    )

    recent_scans = cur.fetchall()

    # TOP DANGEROUS URL
    cur.execute(
        """
        SELECT
            url,
            risk_score
        FROM scanned_urls
        WHERE user_id = %s
        ORDER BY risk_score DESC
        LIMIT 1
        """,
        (user_id,)
    )

    top_threat = cur.fetchone()

    # DAILY ACTIVITY TREND
    cur.execute(
        """
        SELECT
            DATE(scanned_at),
            COUNT(*)
        FROM scanned_urls
        WHERE user_id = %s
        GROUP BY DATE(scanned_at)
        ORDER BY DATE(scanned_at)
        """,
        (user_id,)
    )

    activity_data = cur.fetchall()

    activity_dates = [
        str(row[0])
        for row in activity_data
    ]

    activity_counts = [
        row[1]
        for row in activity_data
    ]

    cur.close()
    conn.close()

    return render_template(
        'dashboard.html',
        total_scans=total_scans,
        phishing_count=phishing_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        average_risk=round(average_risk, 2),
        threat_level=threat_level,
        recent_scans=recent_scans,
        top_threat=top_threat,
        activity_dates=activity_dates,
        activity_counts=activity_counts
    )

@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if request.method == 'POST':

        try:
            _require_csrf_token()
            _enforce_rate_limit('signup')
        except (CsrfError, RateLimitError) as exc:
            if wants_json_response():
                return jsonify({'error': str(exc)}), 403 if isinstance(exc, CsrfError) else 429

            return make_response(str(exc), 403 if isinstance(exc, CsrfError) else 429)

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = hash_password(password)

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                cur.close()
                conn.close()
                if wants_json_response():
                    return jsonify({'error': 'An account with this email already exists.'}), 409
                return make_response('An account with this email already exists.', 409)

            cur.execute(
                """
                INSERT INTO users
                (username, email, password_hash)
                VALUES (%s, %s, %s)
                """,
                (username, email, hashed_password)
            )

            conn.commit()

            cur.close()
            conn.close()

            if wants_json_response():
                return jsonify({'success': 'Account created successfully'}), 201
            
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        except psycopg2.Error as e:
            # Log the error for debugging
            app.logger.error(f"Database error during signup: {e}")
            if wants_json_response():
                return jsonify({'error': 'A database error occurred. Please try again later.'}), 500
            return make_response('A database error occurred. Please try again later.', 500)

        if wants_json_response():
            return jsonify({
                'status': 'ok',
                'message': 'Account created. Please sign in.',
                'next_view': 'login',
            })

        return redirect('/login')

    return render_template('login.html', auth_view='signup')

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        try:
            _require_csrf_token()
            _enforce_rate_limit('login')
        except (CsrfError, RateLimitError) as exc:
            if wants_json_response():
                return jsonify({'error': str(exc)}), 403 if isinstance(exc, CsrfError) else 429

            return make_response(str(exc), 403 if isinstance(exc, CsrfError) else 429)

        email = request.form['email']
        password = request.form['password']

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute(
                """
                SELECT id, username, password_hash, is_admin
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            user = cur.fetchone()

            cur.close()
            conn.close()
        except psycopg2.Error as e:
            app.logger.error(f"Database error during login: {e}")
            if wants_json_response():
                return jsonify({'error': 'A database error occurred. Please try again later.'}), 500
            return make_response('A database error occurred. Please try again later.', 500)

        if user:

            user_id = user[0]
            username = user[1]
            hashed_password = user[2]
            is_admin = bool(user[3])

            if verify_password(password, hashed_password):

                session.clear()

                session.permanent = True

                session['user_id'] = user_id
                session['username'] = username
                session['is_admin'] = is_admin

                if wants_json_response():
                    return jsonify({'status': 'ok', 'next_view': ''})

                return redirect('/')

            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute(
                """
                INSERT INTO audit_logs (action)
                VALUES (%s)
                """,
                (f"Failed login attempt for: {email}",)
            )

            conn.commit()

            cur.close()
            conn.close()

        if wants_json_response():
            return jsonify({'error': 'Invalid Credentials'}), 401

        return "Invalid Credentials"

    return render_template('login.html', auth_view='login')

@app.route('/logout')
def logout():

    username = session.get('username')

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO audit_logs (action)
        VALUES (%s)
        """,
        (f"User logged out: {username}",)
    )

    conn.commit()

    cur.close()
    conn.close()

    session.clear()

    return redirect('/login')

if __name__ == '__main__':
    app.run()