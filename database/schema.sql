CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100),
    email VARCHAR(100) UNIQUE,
    password_hash TEXT,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scanned_urls (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    url TEXT NOT NULL,
    prediction VARCHAR(20),
    risk_score FLOAT,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE url_features (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scanned_urls(id),
    url_length INTEGER,
    dot_count INTEGER,
    has_https BOOLEAN,
    has_ip BOOLEAN,
    special_chars INTEGER
);

CREATE TABLE feedback (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    url TEXT NOT NULL,
    predicted_label VARCHAR(20),
    correct_label VARCHAR(20),
    risk_score FLOAT,
    feedback VARCHAR(20),
    review_status VARCHAR(20) DEFAULT 'PENDING',
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    action TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);