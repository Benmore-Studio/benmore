-- Migration: add_1_tables_add_5_cols
-- Generated: 20261109T210704Z
-- Schema-From: 6b32decfffafd8ccc0687d9a275ad932ea3c744ffc5eea0a0ee115d09ed24610
-- Schema-To: 68c524cb88b7d4770814196e03fc04d730f21f509625fa4b0d1c2584d9dc0b91
--
-- UP --
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    filter TEXT,
    window TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE projects ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;
ALTER TABLE projects ADD COLUMN slug TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_projects_slug ON projects(slug);
ALTER TABLE tasks ADD COLUMN range INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_projects_priority ON projects(priority);
CREATE TABLE "memberships_migrate_tmp" (project_id INTEGER NOT NULL, user_id INTEGER NOT NULL, level TEXT NOT NULL DEFAULT 'member', joined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (project_id, user_id));
INSERT INTO "memberships_migrate_tmp" ("rowid", "project_id", "user_id", "level") SELECT "rowid", "project_id", "user_id", "level" FROM "memberships";
DROP TABLE "memberships";
ALTER TABLE "memberships_migrate_tmp" RENAME TO "memberships";
CREATE INDEX "idx_bm_memberships_user_id" ON "memberships"("user_id");
ALTER TABLE tasks ADD COLUMN due_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
-- DOWN --
DROP INDEX IF EXISTS idx_projects_priority;
ALTER TABLE memberships DROP COLUMN joined_at;
ALTER TABLE projects DROP COLUMN priority;
DROP INDEX IF EXISTS uniq_projects_slug;
ALTER TABLE projects DROP COLUMN slug;
ALTER TABLE tasks DROP COLUMN range;
ALTER TABLE tasks DROP COLUMN due_at;
DROP TABLE IF EXISTS notes;
