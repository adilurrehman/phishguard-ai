import psycopg2

def get_db_connection():

    conn = psycopg2.connect(
        host="localhost",
        database="phishguard_db",
        user="postgres",
        password="Adilkakar420@"
    )

    return conn