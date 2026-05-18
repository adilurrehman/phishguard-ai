from flask import Flask, request, render_template, redirect, session, make_response
from datetime import datetime, timedelta
from app.predict import predict_url
from app.db import get_db_connection
from app.explanations import generate_reasons
from app.auth import hash_password, verify_password
from app.security import login_required

app = Flask(__name__)

app.secret_key = "SUPER_SECRET_KEY"

# SESSION SECURITY SETTINGS
app.config['SESSION_PERMANENT'] = False

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

app.config['SESSION_COOKIE_HTTPONLY'] = True

app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


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

@app.route('/', methods=['GET', 'POST'])
def home():

    if 'user_id' not in session:
        return redirect('/login')

    result = None

    if request.method == 'POST':

        url = request.form['url']

        prediction, risk_score = predict_url(url)

        reasons = generate_reasons(url)

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
            'reasons': reasons
        }

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
        safe_count=safe_count
    )

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
    if average_risk < 40:
        threat_level = "LOW"
    elif average_risk < 70:
        threat_level = "MEDIUM"
    else:
        threat_level = "HIGH"

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
            SELECT id, username, password_hash
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

            if verify_password(password, hashed_password):

                session.clear()

                session.permanent = True

                session['user_id'] = user_id
                session['username'] = username

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