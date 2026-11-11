-- Migration: add_3_tables
-- Generated: 20261109T210602Z
-- Schema-From: 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945
-- Schema-To: 6b32decfffafd8ccc0687d9a275ad932ea3c744ffc5eea0a0ee115d09ed24610
--
-- UP --
CREATE TABLE IF NOT EXISTS memberships (
    project_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    level TEXT NOT NULL DEFAULT 'member',
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    key TEXT NOT NULL UNIQUE,
    desc TEXT,
    action TEXT NOT NULL DEFAULT 'none',
    offset INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    first TEXT,
    last TEXT,
    end DATETIME,
    plan TEXT,
    query TEXT,
    view INTEGER NOT NULL DEFAULT 0,
    cast TEXT,
    raise REAL,
    quantity INTEGER NOT NULL DEFAULT 1,
    price REAL NOT NULL DEFAULT 0,
    amount REAL NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME,
    FOREIGN KEY (project_id) REFERENCES projects(id)
);

CREATE INDEX IF NOT EXISTS idx_projects_user_id_created_at ON projects(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_project_id ON tasks(project_id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_tasks_project_id_title ON tasks(project_id, title);
CREATE TRIGGER IF NOT EXISTS trg_projects_updated_at_updated
AFTER UPDATE ON projects
FOR EACH ROW WHEN NEW.updated_at IS OLD.updated_at AND (NEW.updated_at IS NULL OR julianday(NEW.updated_at) < julianday(CURRENT_TIMESTAMP)) BEGIN
  UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid;
END;
CREATE TRIGGER IF NOT EXISTS trg_tasks_updated_at_updated
AFTER UPDATE ON tasks
FOR EACH ROW WHEN NEW.updated_at IS OLD.updated_at AND (NEW.updated_at IS NULL OR julianday(NEW.updated_at) < julianday(CURRENT_TIMESTAMP)) BEGIN
  UPDATE tasks SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid;
END;

-- DOWN --
DROP TABLE IF EXISTS tasks;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS memberships;
