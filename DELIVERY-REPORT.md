# DevVault delivery report

**Prepared:** 15 October 2026
**Application:** DevVault — local developer portfolio and project showcase
**Implementation:** Python 3 / Flask, SQLite, HTML, CSS, and browser-side JavaScript

## Package contents

This repository contains the application source, project assets, documentation, Python requirements, and `Start DevVault.bat` one-click Windows launcher. The virtual environment, Python bytecode caches, local database, session-signing key, and user credentials are excluded.

## Implemented capabilities

- First-run local username/password setup, sign-in, sign-out, and password changes.
- Password hashes in SQLite, a locally generated session-signing key, CSRF checks on account forms, secure cookie settings, and no-store headers for authenticated pages.
- Local developer name, headline, bio, and technical skills, with JSON profile import/export.
- Project creation, editing, deletion, folder selection, language tags, free-text search, language filters, and exact comma-separated tag filters.
- A curated 41-language selector that retains unlisted language names on existing projects.
- Python script selection and explicit local execution with bounded output and timeout.
- Recursive code scans, syntax and TODO/FIXME findings, generated tasks, and saved file/line metrics.
- Persistent execution history, run totals, success rate, and average runtime.
- Reviewer names, 1–5 star project ratings, feedback notes, per-project averages, and recent feedback in portfolio output.
- Standalone per-project reports and a portable HTML portfolio export.
- Local first-run setup; no remote account provider or cloud dependency is required for app features.

## Validation completed

- Python syntax and Pylance diagnostics checked for the modified Python modules.
- Isolated Flask integration checks passed for profile save/import/export, language and exact-tag filters, review validation and persistence, dashboard metrics, and portfolio export.
- An existing SQLite database was upgraded in a temporary test location; the existing project record remained intact.
- Local account checks passed for first-run setup, invalid and valid passwords, password hashing, sign-in/out, password changes, CSRF enforcement, secure cookie attributes, and protected portfolio routes.
- The latest running local app returned HTTP 200 for the setup, profile, project catalog, dashboard, stylesheet, and portfolio-export routes during the related feature checks.
- The packaged Windows launcher was extracted into a fresh temporary folder, created its own virtual environment and Flask install, and served the first-run account-setup page over HTTP 200 on a test port.
- The launcher waits for the local HTTP endpoint before opening the browser and opens the existing app instead of starting a duplicate when its configured port is already in use.

## First-run workflow

On first launch, create a local username and a password between 12 and 128 characters. No default account or credentials are included. Python 3.11 or newer is required. The launcher creates a local virtual environment and installs Flask from the included requirements file if necessary. Keep its window open while using the app.

## Local data and security notes

SQLite data and the session-signing key are stored outside the source folder in `%LOCALAPPDATA%\\DevVault\\`. They are deliberately excluded from the source package. The local account is a single-user convenience/privacy boundary for a loopback development app; this is not a hardened multi-user hosting service. Script timeouts are not a security sandbox, so only execute trusted project code.

The portfolio export excludes local filesystem paths. It includes only the saved profile, project descriptions and tags, recorded metrics, run counts, and recent reviewer feedback. Review notes are local data; inspect the export before sharing it.

## Scope notes

- The Windows launcher is a one-click `.bat` launcher, not a compiled standalone `.exe`; it requires a Python installation.
- Email sign-up, public cloud hosting, remote reviewer access, and password-recovery email are not included.
- The included Next.js scaffold is retained as source, while the supported one-click launcher starts the Flask/SQLite app.
