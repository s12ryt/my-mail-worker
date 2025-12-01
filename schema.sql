DROP TABLE IF EXISTS mails;
CREATE TABLE IF NOT EXISTS mails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user TEXT NOT NULL,
    recipient TEXT NOT NULL,
    sender TEXT,
    subject TEXT,
    content TEXT,
    created_at INTEGER,
    share_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_mails_owner ON mails(owner_user);
CREATE INDEX IF NOT EXISTS idx_mails_share ON mails(share_id);
