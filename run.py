from flask import Flask, request, render_template, redirect, session, make_response, jsonify
import validators
from datetime import datetime, timedelta
from app.analysis_engine import analyze_url
from app.db import get_db_connection
from app.auth import hash_password, verify_password
from app.security import login_required, admin_required

app = Flask(__name__)

app.secret_key = "SUPER_SECRET_KEY"

# SESSION SECURITY SETTINGS
app.config['SESSION_PERMANENT'] = False

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

app.config['SESSION_COOKIE_HTTPONLY'] = True

app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


def wants_json_response():

    return request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.best == 'application/json'


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

    response.headers['Cache-Control'] = 'no-store'

    return response


@app.route('/feedback', methods=['POST'])
@login_required
def feedback():

    url = request.form['url']
    predicted_label = request.form['predicted_label']
    risk_score = request.form['risk_score']
    feedback_value = request.form['feedback']

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
        return jsonify({"status": "ok"})

    return redirect('/')


@app.route('/admin/feedback', methods=['GET', 'POST'])
@admin_required
def admin_feedback():

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':

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

@app.route('/', methods=['GET', 'POST'])
def home():

    if 'user_id' not in session:
        return redirect('/login')

    result = None

    if request.method == 'POST':

        url = request.form.get('url', '')
        url = url.strip()

        # EMPTY CHECK
        if not url:
            if wants_json_response():
                return jsonify({'error': 'URL cannot be empty'}), 400

            return render_template('index.html', error="URL cannot be empty")

        # URL FORMAT VALIDATION
        if not validators.url(url):
            if wants_json_response():
                return jsonify({'error': 'Invalid URL format'}), 400

            return render_template('index.html', error="Invalid URL format")

        analysis = analyze_url(url)
        prediction = analysis['prediction']
        risk_score = analysis['risk_score']
        reasons = analysis['reasons']
        safety_tips = analysis['safety_tips']

        # DATABASE SAVE
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
                prediction,
                risk_score
            )
        )

        cur.execute(
            """
            INSERT INTO audit_logs (action)
            VALUES (%s)
            """,
            (f"URL scanned: {url}",)
        )

        conn.commit()

        cur.close()
        conn.close()

        result = {
            'url': url,
            'prediction': prediction,
            'risk_score': risk_score,
            'reasons': reasons,
            'safety_tips': safety_tips,
        }

    if wants_json_response() and request.method == 'POST':
        return jsonify({'result_html': render_template('_analysis_result.html', result=result)})

    return render_template('index.html', result=result)

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

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = hash_password(password)

        conn = get_db_connection()
        cur = conn.cursor()

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

        return redirect('/login')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

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

        return "Invalid Credentials"

    return render_template('login.html')

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
    app.run(debug=True)