# DuoBond

A private two-member chat app with device-local encryption.

## Current implementation
- Supabase email/password authentication
- Two-member access controlled by Supabase RLS
- New messages encrypted in the browser using Web Crypto (P-256 ECDH, HKDF-SHA-256, AES-256-GCM)
- Private device key pair stored in browser IndexedDB; private key is non-extractable and is not uploaded
- Public-key fingerprint comparison before encrypted chat is unlocked
- Delivery and read receipts (Sent / Delivered / Seen)
- Older messages remain readable as legacy plaintext and are clearly labelled
- Installable PWA

## Important cryptographic limitations
This is DuoBond's initial device-only encryption implementation, not the Signal protocol. It uses a static ECDH-derived chat key and does **not** provide forward secrecy or a ratchet. Anyone who obtains the device private key and the corresponding message history may be able to decrypt that history. Do not treat it as a high-assurance secure messenger.

Fingerprint verification is essential: compare the displayed partner fingerprint through a separate trusted channel before confirming it. If a device key changes unexpectedly, stop and verify it again. The first device must reload after the other account has registered its key.

Only one active device key per account is supported in this version. Adding a new phone/browser replaces that account's public key; old messages may no longer decrypt on a device without the original private key.

## No-backup warning
Private keys are stored only in that browser's IndexedDB. Clearing site data, deleting browser storage, uninstalling/resetting the device, or losing the device can permanently destroy the key. There is no cloud backup or recovery. Signing in on another device does not restore old decryption keys.

## Supabase setup
The database requires:
- `public.duo_members` with the two approved Auth user IDs
- `public.messages` with RLS enabled
- `public.duo_device_keys` and `public.message_receipts` created by `supabase-e2ee-migration.sql`
- Realtime enabled for messages, device keys, and receipts

Run `supabase-e2ee-migration.sql` once in Supabase SQL Editor. Never expose a service-role or secret key in frontend code. The publishable key is intended for browser use only with correctly configured RLS.

## Deployment
GitHub Pages deploys from the main branch root. After updates, refresh the site; if an old version remains cached, close the installed PWA/browser tab and reopen it.
