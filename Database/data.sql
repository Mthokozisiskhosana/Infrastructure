-- ============================================
-- CIRIS seed data — run AFTER tables.sql
-- ============================================

-- Promote an existing (already registered) account to supervisor so it can
-- log in to municipal-login.html and create other staff via /admin/create-staff.
-- Register the account through login.html first, then run this.
UPDATE Users SET role = 'supervisor' WHERE email = 'mthokozisiskhosana17@gmail.com';

-- Check it worked:
-- SELECT id, email, role FROM Users WHERE email = 'mthokozisiskhosana17@gmail.com';

-- To create additional test staff without the UI, use:
--   node create-worker.js "Jane" "Doe" "jane@example.com" "0821234567" "TempPass123!" municipal_worker
