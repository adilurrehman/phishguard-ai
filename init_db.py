from database import get_db_connection

conn = get_db_connection()

cur = conn.cursor()

# USERS TABLE
cur.execute("""

CREATE TABLE IF NOT EXISTS users (

    id SERIAL PRIMARY KEY,

    username VARCHAR(100),

    email VARCHAR(255) UNIQUE,

    password VARCHAR(255)

);

""")

# SCANNED_URLS
cur.execute("""

CREATE TABLE IF NOT EXISTS scanned_urls (

    id SERIAL PRIMARY KEY,

    user_id INTEGER,

    url TEXT NOT NULL,

    prediction VARCHAR(50),

    risk_score FLOAT,

    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);

""")

# AUDIT LOGS
cur.execute("""

CREATE TABLE IF NOT EXISTS audit_logs (

    id SERIAL PRIMARY KEY,

    action TEXT,
    
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);

""")

# FEEDBACK
cur.execute("""

CREATE TABLE IF NOT EXISTS feedback (

    id SERIAL PRIMARY KEY,

    url TEXT,

    predicted_label VARCHAR(50),

    correct_label VARCHAR(50),

    risk_score FLOAT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);

""")

conn.commit()

cur.close()
conn.close()

print("Database initialized successfully.")