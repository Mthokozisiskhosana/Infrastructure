-- ============================================
-- CIRIS database schema
-- Matches every table/column server.js uses.
-- Safe to run on a fresh database AND on an existing one: tables are
-- created only if missing, and columns added later in the project are
-- added with ADD COLUMN IF NOT EXISTS.
-- Run order: tables.sql, then data.sql
-- ============================================

CREATE EXTENSION IF NOT EXISTS postgis;

-- ============================================
-- USERS
-- ============================================
CREATE TABLE IF NOT EXISTS Users (
    id                          SERIAL PRIMARY KEY,
    first_name                  VARCHAR(100) NOT NULL,
    last_name                   VARCHAR(100) NOT NULL,
    email                       VARCHAR(255) NOT NULL UNIQUE,
    phone                       VARCHAR(20)  NOT NULL,
    password                    VARCHAR(255) NOT NULL,          -- bcrypt hash
    profile_picture             TEXT,                           -- "/uploads/profiles/<uuid>.jpg"
    reset_token                 VARCHAR(255),                   -- sha256 of the OTP
    reset_token_expiry          TIMESTAMP
);

-- Role-based access
ALTER TABLE Users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'community_member';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_users_role') THEN
        ALTER TABLE Users
            ADD CONSTRAINT chk_users_role
            CHECK (role IN ('community_member', 'municipal_worker', 'supervisor', 'admin'));
    END IF;
END $$;

-- Force new staff to set their own password on first login
ALTER TABLE Users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;

-- Email-change verification (pending email must be confirmed with a code)
ALTER TABLE Users ADD COLUMN IF NOT EXISTS pending_email              VARCHAR(255);
ALTER TABLE Users ADD COLUMN IF NOT EXISTS pending_email_token        VARCHAR(255);
ALTER TABLE Users ADD COLUMN IF NOT EXISTS pending_email_token_expiry TIMESTAMP;

-- POPIA consent record: when the user ticked the consent box at
-- registration, and which version of the wording they agreed to
-- (POPIA_CONSENT_VERSION in server.js). NULL = registered before consent
-- was collected.
ALTER TABLE Users ADD COLUMN IF NOT EXISTS popia_consent_at      TIMESTAMP;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS popia_consent_version VARCHAR(20);

-- Session control: bumping token_version (password change/reset,
-- deactivation) signs the user out everywhere; is_active = false blocks
-- sign-in for staff who have left. server.js also adds these on startup.
ALTER TABLE Users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS is_active     BOOLEAN NOT NULL DEFAULT true;

-- ============================================
-- REPORTS
-- ============================================
CREATE TABLE IF NOT EXISTS Reports (
    id           SERIAL PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
    description  VARCHAR(1000) NOT NULL,
    image        TEXT,                                          -- "/uploads/reports/<uuid>.jpg" (file on disk, see imageStorage.js)
    location     VARCHAR(100),                                  -- "lat, lng"
    status       VARCHAR(50) NOT NULL DEFAULT 'Received',       -- Received | Under Review | Assigned | Resolved
    date         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- AI classification result (from the ciris-ai-service /classify endpoint)
ALTER TABLE Reports ADD COLUMN IF NOT EXISTS ai_category   VARCHAR(100);
ALTER TABLE Reports ADD COLUMN IF NOT EXISTS ai_confidence REAL;            -- 0.0 – 1.0

-- Auto-archiving of resolved reports (see archiveOldResolvedReports in server.js)
ALTER TABLE Reports ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP;
ALTER TABLE Reports ADD COLUMN IF NOT EXISTS is_archived BOOLEAN NOT NULL DEFAULT false;

-- After-repair photo uploaded by municipal staff (uploading it marks the report Resolved)
ALTER TABLE Reports ADD COLUMN IF NOT EXISTS after_image    TEXT;          -- "/uploads/repairs/<uuid>.jpg"
ALTER TABLE Reports ADD COLUMN IF NOT EXISTS after_image_at TIMESTAMP;

-- Optional PostGIS column for future spatial duplicate-detection queries.
-- Not used by server.js yet (it does the distance check in JS).
ALTER TABLE Reports ADD COLUMN IF NOT EXISTS geo_location geography(Point, 4326);

CREATE INDEX IF NOT EXISTS idx_reports_user_id  ON Reports(user_id);
CREATE INDEX IF NOT EXISTS idx_reports_status   ON Reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_archived ON Reports(is_archived);
CREATE INDEX IF NOT EXISTS idx_reports_geo      ON Reports USING GIST (geo_location);

-- ============================================
-- FEEDBACK
-- ============================================
CREATE TABLE IF NOT EXISTS Feedback (
    id       SERIAL PRIMARY KEY,
    user_id  INTEGER NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
    message  TEXT NOT NULL,
    date     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_read  BOOLEAN NOT NULL DEFAULT false
);

-- Staff replies to feedback
ALTER TABLE Feedback ADD COLUMN IF NOT EXISTS reply_message TEXT;
ALTER TABLE Feedback ADD COLUMN IF NOT EXISTS reply_date    TIMESTAMP;
ALTER TABLE Feedback ADD COLUMN IF NOT EXISTS replied_by    INTEGER REFERENCES Users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON Feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_is_read ON Feedback(is_read);

-- ============================================
-- NOTIFICATIONS
-- user_id NULL  = shared municipal staff inbox
-- user_id set   = personal inbox for that community member
-- type: 'report' | 'feedback'                  -> staff inbox
--       'feedback_reply' | 'report_status'     -> resident inbox
-- related_id: id of the Report or Feedback row the notification is about
-- ============================================
CREATE TABLE IF NOT EXISTS Notifications (
    id          SERIAL PRIMARY KEY,
    type        VARCHAR(20)  NOT NULL,
    related_id  INTEGER      NOT NULL,
    title       VARCHAR(255) NOT NULL,
    message     TEXT         NOT NULL,
    user_id     INTEGER REFERENCES Users(id) ON DELETE CASCADE,
    is_read     BOOLEAN   NOT NULL DEFAULT false,
    date        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Recreated on every run so the allowed list stays in sync with server.js
-- (older databases only allowed report/feedback/feedback_reply).
ALTER TABLE Notifications DROP CONSTRAINT IF EXISTS notifications_type_check;
ALTER TABLE Notifications
    ADD CONSTRAINT notifications_type_check
    CHECK (type IN ('report', 'feedback', 'feedback_reply', 'report_status'));

CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON Notifications(user_id, is_read);

-- ============================================
-- LOGIN ATTEMPTS (brute-force protection — see loginSecurity.js)
-- server.js also creates this automatically on startup.
-- attempt_key: 'login:<email>' | 'ip:<address>' | 'reset:<email>' | 'emailchange:<userId>'
-- ============================================
CREATE TABLE IF NOT EXISTS LoginAttempts (
    attempt_key     VARCHAR(255) PRIMARY KEY,
    failed_count    INTEGER   NOT NULL DEFAULT 0,
    lockouts        INTEGER   NOT NULL DEFAULT 0,   -- lockouts in a row (30s, 1m, 5m, 15m)
    locked_until    TIMESTAMP,
    last_failed_at  TIMESTAMP
);
