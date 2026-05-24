import os

import psycopg2

def _ensure_schema(conn):

    cur = conn.cursor()

    cur.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE"
    )

    cur.execute(
        "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS review_status VARCHAR(20) DEFAULT 'PENDING'"
    )

    cur.execute(
        "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS reviewed_by INTEGER"
    )

    cur.execute(
        "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP"
    )

    # Ensure core feedback columns exist for older DBs
    cur.execute(
        "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS user_id INTEGER"
    )

    cur.execute(
        "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS url TEXT"
    )

    cur.execute(
        "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS predicted_label VARCHAR(20)"
    )

    cur.execute(
        "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS correct_label VARCHAR(20)"
    )

    cur.execute(
        "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS risk_score FLOAT"
    )

    cur.execute(
        "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS feedback VARCHAR(20)"
    )

    cur.execute(
        "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
    )

    conn.commit()

    cur.close()

def get_db_connection():
    return psycopg2.connect(
        os.getenv("DATABASE_URL")
    )