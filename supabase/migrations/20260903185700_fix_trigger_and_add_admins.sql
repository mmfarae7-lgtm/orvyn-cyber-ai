/*
# Fix handle_new_user trigger function

## Problem
The trigger function `handle_new_user` was failing on signup, causing "Database error saving new user".
This was due to missing search_path and RLS interaction issues.

## Changes
- Recreate the function with a secure, fixed search_path
- Auto-set is_admin = true for the three authorized admin emails
- Drop and recreate the trigger
*/

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, display_name, is_admin)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'display_name', ''),
    NEW.email IN ('m.m.farae7@gmail.com', 'm.m.binfarae@gmail.com', 'mh566816@gmail.com')
  );
  RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Also update any existing profiles for admin emails
UPDATE public.profiles p
SET is_admin = true
FROM auth.users u
WHERE p.id = u.id
  AND u.email IN ('m.m.farae7@gmail.com', 'm.m.binfarae@gmail.com', 'mh566816@gmail.com');