CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    delivered_at TEXT,
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL
);
