# DuoBond

A private, two-member messaging web app designed for Android-first installation.

## Current first version
- Email/password sign-in through Supabase Auth
- Private text messages stored in Supabase
- Realtime incoming messages
- Installable PWA shell for Android
- Responsive dark interface

## Deployment
Enable GitHub Pages for this repository:
1. Open **Settings → Pages**.
2. Under **Build and deployment**, choose **Deploy from a branch**.
3. Select **main** and **/(root)**, then Save.
4. Wait for the Pages URL to become available.

## Supabase
This app uses the Supabase project configured in `index.html`. The browser key is a publishable key; never put a service-role or secret key in frontend code.

The existing database must have:
- `public.duo_members` with the two approved Auth user IDs
- `public.messages` with RLS enabled
- Policies that allow only approved duo members to read messages and insert messages where `sender_id = auth.uid()`
- Realtime enabled for `public.messages`

## Important security notes
This first version is **not end-to-end encrypted**. Messages are protected by Supabase authentication and row-level security, but the service/database operators can access stored message content. Do not use this as a secure vault for highly sensitive information.

Keep membership changes restricted to trusted administrative access. Do not expose Supabase secret/service-role keys. Before inviting anyone, verify the RLS policies in Supabase.

## Current limitations
Text chat only. No image/file attachments, push notifications, read receipts, typing status, or end-to-end encryption yet.
