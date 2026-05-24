import os
import psycopg2


def get_db_connection():
    """Return a new psycopg2 connection using DATABASE_URL from the environment."""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL must be set in the environment or .env file.")

    return psycopg2.connect(database_url)
