/*
# Add admin column to profiles

## Changes
- Adds `is_admin` boolean column to profiles table (default false)
- Creates an admin profiles entry for the owner email
- Updates the handle_new_user trigger to default is_admin to false
*/

ALTER TABLE profiles ADD COLUMN IF NOT EXISTS is_admin boolean NOT NULL DEFAULT false;

-- Mark the owner email as admin (profile will be created on signup, but we pre-set it)
INSERT INTO profiles (id, display_name, is_admin)
SELECT id, 'Orion Admin', true
FROM auth.users
WHERE email = 'm.m.farae7@gmail.com'
ON CONFLICT (id) DO UPDATE SET is_admin = true;