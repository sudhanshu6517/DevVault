# DevVault — Codebase Intelligence Lab

A local Flask + SQLite desktop-style developer utility for registering Python projects, running a verifiable Project Autopsy, executing explicitly selected scripts, tracking fix tasks, and exporting standalone HTML reports.

## Windows setup

1. Install Python 3.11 or newer from python.org and enable **Add Python to PATH**.
2. Double-click **Start DevVault.bat** in the repository folder. On first launch it creates the local Python environment and installs the app requirements if needed.
3. On the first browser visit, create a local username and password (12–128 characters). Use **Peek** to check password entries before submitting. Later visits ask you to sign in. Change your password from **Developer Profile**.
4. DevVault opens in your browser at `http://127.0.0.1:5000`. Keep the launcher window open while using the app; press **Ctrl+C** in it to stop the server.

For manual setup instead, create the environment with `py -3 -m venv .venv`, install dependencies with `.venv\Scripts\python.exe -m pip install -r devvault\requirements.txt`, and start with `pnpm dev` from the repository root.

The SQLite database and randomly generated session-signing key are stored in `%LOCALAPPDATA%\DevVault\`, not in the source folder. The local username/password is stored in the SQLite database with the password hashed. If you forget the password, DevVault currently has no cloud or email recovery. The included `sample_projects/working_project` is safe to run. The `broken_project` is intended only for scanning and contains a deliberate syntax error.

## Features

- Password-protected local sign-in with hashed password storage, profile access, and password changes; there is no cloud account or authentication service.
- Local developer profile with bio and skills, including JSON import/export.
- Local project catalog with create/edit/delete, full-text keyword matching, and language/tag filters.
- Language selection includes popular web, systems, scripting, data, and functional languages; existing custom language values remain selectable when editing older project records.
- Native folder selection when registering or editing projects, and native Python-file selection in the script runner. Browse dialogs run on the local Windows machine; the selected script must be inside its registered project.
- Recursive scan using `pathlib` and `ast`, excluding generated directories and symlinks.
- Saved file and line metrics, syntax errors, TODO/FIXME findings, local import observations, and generated fix tasks.
- Explicit Python execution through `sys.executable`, no shell, bounded output, and configurable timeout.
- Persistent execution history and output inspection, with run totals, average execution time, and latest scan metrics on the dashboard.
- Per-project reviewer notes and 1–5 star code-quality ratings stored in SQLite.
- Standalone portfolio HTML export with profile, projects, latest scan metrics, run counts, and recent feedback; individual project reports remain available.

## Manual test checklist

- Register `sample_projects/working_project`, refresh, and confirm it persists.
- On a clean local database, create an account once, sign out, sign in again, and change the password.
- Run an autopsy and confirm Python file counts and local import findings.
- Register `sample_projects/broken_project`, run an autopsy, and confirm the syntax error plus TODO/FIXME warnings.
- Run `main.py` from the working project and inspect Run History.
- Add a profile, export its JSON backup, then import it again.
- Filter the project catalog by language and tag.
- Add reviewer feedback, then export and inspect the portfolio summary.
- Edit task statuses, reload the app, and confirm they remain saved.
- Download a report and open it offline.
- Try an invalid folder and invalid script path; confirm a readable error appears.
- On the local machine, use **Browse…** to choose a project folder and Python script. Cancel a dialog and confirm the existing input stays unchanged.
- Submit an invalid project folder and confirm all entered project details remain in the form.
- Delete a project only after the confirmation prompt.

DevVault is intentionally local-only and listens on loopback. Its local password protects the browser session on this computer; it is not a multi-user hosting or remote security system. Script timeouts reduce accidental hangs but are not a complete security sandbox; use it only with trusted code.
