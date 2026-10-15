import os, sqlite3
from pathlib import Path
from flask import g

APP_DIR = Path(os.getenv("LOCALAPPDATA", Path.home())) / "DevVault"
DB_PATH = APP_DIR / "devvault.sqlite3"

def get_db():
    if "db" not in g:
        APP_DIR.mkdir(parents=True, exist_ok=True); g.db=sqlite3.connect(DB_PATH); g.db.row_factory=sqlite3.Row; g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

def close_db(exception=None):
    db=g.pop("db",None)
    if db: db.close()

def init_db():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    db=sqlite3.connect(DB_PATH)
    db.executescript('''CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '', folder_path TEXT NOT NULL, language TEXT DEFAULT 'Python', tags TEXT DEFAULT '', accessed_at TEXT DEFAULT CURRENT_TIMESTAMP, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS local_account(id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS developer_profile(id INTEGER PRIMARY KEY CHECK(id=1), full_name TEXT NOT NULL DEFAULT '', headline TEXT NOT NULL DEFAULT '', bio TEXT NOT NULL DEFAULT '', skills TEXT NOT NULL DEFAULT '', updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
    INSERT OR IGNORE INTO developer_profile(id) VALUES(1);
    CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, created_at TEXT DEFAULT CURRENT_TIMESTAMP, total_files INTEGER, total_folders INTEGER, python_files INTEGER, physical_lines INTEGER, non_empty_lines INTEGER);
    CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, severity TEXT NOT NULL, description TEXT NOT NULL, file_path TEXT, line_number INTEGER, suggestion TEXT);
    CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL, title TEXT NOT NULL, description TEXT NOT NULL, file_path TEXT, line_number INTEGER, priority TEXT DEFAULT 'Medium', status TEXT DEFAULT 'Open', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS executions(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, script_path TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, duration REAL, exit_code INTEGER, status TEXT, stdout TEXT DEFAULT '', stderr TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, reviewer TEXT NOT NULL, rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5), note TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE INDEX IF NOT EXISTS reviews_project_created ON reviews(project_id, created_at DESC);''')
    db.commit(); db.close()

def get_project(project_id): return get_db().execute("SELECT * FROM projects WHERE id=?",(project_id,)).fetchone()
def get_latest_scan(project_id): return get_db().execute("SELECT * FROM scans WHERE project_id=? ORDER BY created_at DESC LIMIT 1",(project_id,)).fetchone()
