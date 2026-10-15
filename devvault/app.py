from flask import Flask, abort, flash, jsonify, make_response, redirect, render_template, request, session, url_for, send_file
from pathlib import Path
from io import BytesIO
from datetime import timedelta
import json
import os
import re
import secrets
import sqlite3
import hmac
import tkinter as tk
from tkinter import filedialog
from werkzeug.security import check_password_hash, generate_password_hash

from database import APP_DIR, init_db, get_db, get_project, get_latest_scan
from scanner import run_autopsy
from runner import execute_script
from reports import build_report

app = Flask(__name__)
def _load_session_secret():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    secret_path = APP_DIR / "session.key"
    try:
        existing = secret_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        existing = ""
    if existing:
        return existing
    generated = secrets.token_hex(32)
    secret_path.write_text(generated, encoding="utf-8")
    return generated

app.secret_key = os.environ.get("DEVVAULT_SECRET_KEY") or _load_session_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=14),
)
init_db()

LANGUAGE_GROUPS = (
    ("Popular", ("Python", "JavaScript", "TypeScript", "Java", "C", "C++", "C#", "Go", "Rust", "PHP", "Ruby", "Swift", "Kotlin")),
    ("Web", ("HTML", "CSS", "SQL", "Dart", "Vue", "Svelte")),
    ("Systems and compiled", ("Assembly", "Objective-C", "Zig", "Fortran", "COBOL", "Visual Basic .NET", "F#")),
    ("Scripting and data", ("R", "Bash", "PowerShell", "MATLAB", "Julia", "Perl", "Lua", "Groovy")),
    ("Functional and other", ("Scala", "Haskell", "Elixir", "Erlang", "Clojure", "OCaml", "Solidity")),
)
LANGUAGES = tuple(language for _, languages in LANGUAGE_GROUPS for language in languages)

def _project_catalog(db, query="", language_filter="", tag_filter=""):
    clauses = []
    params = []
    if query:
        clauses.append("(name LIKE ? OR description LIKE ? OR language LIKE ? OR tags LIKE ?)")
        params.extend([f"%{query}%"] * 4)
    if language_filter:
        clauses.append("language = ?")
        params.append(language_filter)
    if tag_filter:
        clauses.append("instr(',' || replace(replace(lower(tags), ', ', ','), ' ,', ',') || ',', ',' || lower(?) || ',') > 0")
        params.append(tag_filter)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    projects = db.execute(f"SELECT * FROM projects{where} ORDER BY accessed_at DESC", params).fetchall()
    tag_rows = db.execute("SELECT tags FROM projects WHERE tags != ''").fetchall()
    tags = sorted({tag.strip() for row in tag_rows for tag in row["tags"].split(",") if tag.strip()}, key=str.casefold)
    language_rows = db.execute("SELECT DISTINCT language FROM projects WHERE language != '' ORDER BY language COLLATE NOCASE").fetchall()
    languages = sorted(set(LANGUAGES).union(row["language"] for row in language_rows), key=str.casefold)
    return projects, languages, tags

def _profile_values(source):
    fields = {}
    for key, label in (("full_name", "Name"), ("headline", "Headline"), ("bio", "Bio")):
        value = source.get(key, "")
        if not isinstance(value, str):
            raise ValueError(f"{label} must be text.")
        fields[key] = value.strip()
    full_name = fields["full_name"]
    headline = fields["headline"]
    bio = fields["bio"]
    raw_skills = source.get("skills", "")
    if isinstance(raw_skills, list):
        if any(not isinstance(skill, str) for skill in raw_skills):
            raise ValueError("Each skill must be text.")
        skills = raw_skills
    elif isinstance(raw_skills, str):
        skills = raw_skills.replace("\n", ",").split(",")
    else:
        raise ValueError("Skills must be a comma-separated string or a list of strings.")
    skills = list(dict.fromkeys(skill.strip() for skill in skills if skill.strip()))
    for field_name, value, limit in (
        ("Name", full_name, 100),
        ("Headline", headline, 160),
        ("Bio", bio, 1200),
    ):
        if len(value) > limit:
            raise ValueError(f"{field_name} must be {limit} characters or fewer.")
    if len(skills) > 30 or any(len(skill) > 80 for skill in skills):
        raise ValueError("Add up to 30 skills, with at most 80 characters per skill.")
    return {
        "full_name": full_name,
        "headline": headline,
        "bio": bio,
        "skills": ", ".join(skills),
    }

@app.context_processor
def inject_globals():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"active_page": request.endpoint or "dashboard", "language_groups": LANGUAGE_GROUPS, "languages": LANGUAGES, "csrf_token": session["csrf_token"]}

@app.before_request
def require_local_account():
    if request.endpoint in {"login", "setup_account", "static"}:
        return None
    account = get_db().execute("SELECT id FROM local_account WHERE id=1").fetchone()
    if not account:
        return redirect(url_for("setup_account"))
    if session.get("account_id") != account["id"]:
        session.clear()
        return redirect(url_for("login"))
    return None

@app.after_request
def add_local_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"
    return response

@app.before_request
def protect_account_forms():
    if request.method == "POST" and request.endpoint in {"setup_account", "login", "logout", "change_password"}:
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            abort(400, description="The form expired or could not be verified. Reload the page and try again.")
    return None

@app.route("/setup", methods=["GET", "POST"])
def setup_account():
    db = get_db()
    if db.execute("SELECT id FROM local_account WHERE id=1").fetchone():
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if not re.fullmatch(r"[a-z0-9_.-]{3,40}", username):
            flash("Choose a username with 3–40 letters, numbers, dots, dashes, or underscores.", "error")
            return render_template("auth.html", auth_mode="setup", username=request.form.get("username", ""))
        if len(password) < 12 or len(password) > 128:
            flash("Choose a password between 12 and 128 characters.", "error")
            return render_template("auth.html", auth_mode="setup", username=request.form.get("username", ""))
        if password != confirmation:
            flash("The passwords do not match.", "error")
            return render_template("auth.html", auth_mode="setup", username=request.form.get("username", ""))
        try:
            db.execute("INSERT INTO local_account(id,username,password_hash) VALUES(1,?,?)", (username, generate_password_hash(password)))
        except sqlite3.IntegrityError:
            flash("A local account was just created. Sign in to continue.", "error")
            return redirect(url_for("login"))
        db.commit()
        session.clear()
        session["account_id"] = 1
        session.permanent = True
        flash("Local account created. Your portfolio is ready.", "success")
        return redirect(url_for("dashboard"))
    return render_template("auth.html", auth_mode="setup", username="")

@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    if not db.execute("SELECT id FROM local_account WHERE id=1").fetchone():
        return redirect(url_for("setup_account"))
    if session.get("account_id") == 1:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        account = db.execute("SELECT id,username,password_hash FROM local_account WHERE id=1 AND username=?", (username,)).fetchone()
        if not account or not check_password_hash(account["password_hash"], password):
            flash("The username or password is incorrect.", "error")
            return render_template("auth.html", auth_mode="login", username=request.form.get("username", ""))
        session.clear()
        session["account_id"] = account["id"]
        session.permanent = True
        flash(f"Welcome back, {account['username']}.", "success")
        return redirect(url_for("dashboard"))
    return render_template("auth.html", auth_mode="login", username="")

@app.post("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))

def _native_picker(kind, initialdir=None):
    root = tk.Tk()
    try:
        root.withdraw()
        root.attributes("-topmost", True)
        root.update()
        if kind == "folder":
            return filedialog.askdirectory(parent=root, initialdir=initialdir or str(Path.home()), title="Choose project folder", mustexist=True)
        return filedialog.askopenfilename(parent=root, initialdir=initialdir, title="Choose Python script", filetypes=[("Python files", "*.py"), ("All files", "*.*")])
    finally:
        root.destroy()

@app.post("/browse/folder")
def browse_folder():
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        abort(403)
    try:
        selected = _native_picker("folder")
    except (OSError, tk.TclError) as exc:
        return jsonify(error=f"Could not open the folder picker: {exc}"), 503
    return jsonify(path=str(Path(selected).resolve())) if selected else jsonify(cancelled=True)

@app.post("/projects/<int:project_id>/browse/script")
def browse_script(project_id):
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        abort(403)
    project = get_project(project_id)
    if not project:
        return jsonify(error="Project not found."), 404
    root = Path(project["folder_path"]).expanduser().resolve()
    if not root.is_dir():
        return jsonify(error="The registered project folder is not accessible."), 400
    try:
        selected = _native_picker("file", str(root))
    except (OSError, tk.TclError) as exc:
        return jsonify(error=f"Could not open the file picker: {exc}"), 503
    if not selected:
        return jsonify(cancelled=True)
    target = Path(selected).resolve()
    try:
        relative_path = target.relative_to(root)
    except ValueError:
        return jsonify(error="Choose a script inside the registered project folder."), 400
    if not target.is_file() or target.suffix.lower() != ".py":
        return jsonify(error="Choose a Python script file."), 400
    return jsonify(path=str(relative_path))

@app.get("/")
def dashboard():
    db = get_db()
    stats = db.execute("""SELECT COUNT(*) projects,
        COALESCE(SUM((SELECT total_files FROM scans s WHERE s.project_id=p.id ORDER BY s.created_at DESC,s.id DESC LIMIT 1)),0) total_files,
        COALESCE(SUM((SELECT python_files FROM scans s WHERE s.project_id=p.id ORDER BY s.created_at DESC,s.id DESC LIMIT 1)),0) python_files,
        COALESCE(SUM((SELECT physical_lines FROM scans s WHERE s.project_id=p.id ORDER BY s.created_at DESC,s.id DESC LIMIT 1)),0) physical_lines,
        (SELECT COUNT(*) FROM executions) executions,
        (SELECT COUNT(*) FROM executions WHERE status='Success') successes,
        (SELECT COUNT(*) FROM executions WHERE status!='Success') failures,
        (SELECT AVG(duration) FROM executions WHERE duration IS NOT NULL) average_duration
        FROM projects p""").fetchone()
    projects = db.execute("SELECT * FROM projects ORDER BY accessed_at DESC LIMIT 5").fetchall()
    scans = db.execute("SELECT s.*, p.name project_name FROM scans s JOIN projects p ON p.id=s.project_id ORDER BY s.created_at DESC LIMIT 5").fetchall()
    profile = db.execute("SELECT * FROM developer_profile WHERE id=1").fetchone()
    return render_template("dashboard.html", stats=stats, projects=projects, scans=scans, profile=profile)

@app.route("/projects", methods=["GET", "POST"])
def projects():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip(); folder = request.form.get("folder_path", "").strip()
        language = request.form.get("language", "Python").strip() or "Python"
        error = None
        if not name:
            error = "Enter a project name."
        elif not folder or not Path(folder).expanduser().is_dir():
            error = "Choose or enter an accessible project folder."
        if error:
            flash(error, "error")
            q = request.form.get("q", "").strip()
            language_filter = request.form.get("language_filter", "").strip()
            tag_filter = request.form.get("tag_filter", "").strip()
            rows, available_languages, available_tags = _project_catalog(db, q, language_filter, tag_filter)
            return render_template("projects.html", projects=rows, query=q, form_data=request.form, language_filter=language_filter, tag_filter=tag_filter, available_languages=available_languages, available_tags=available_tags)
        else:
            folder = str(Path(folder).expanduser().resolve())
            db.execute("INSERT INTO projects(name,description,folder_path,language,tags) VALUES(?,?,?,?,?)", (name, request.form.get("description",""), folder, language, request.form.get("tags",""))); db.commit(); flash("Project registered.", "success")
        return redirect(url_for("projects", q=request.form.get("q", "").strip(), language_filter=request.form.get("language_filter", "").strip(), tag_filter=request.form.get("tag_filter", "").strip()))
    q = request.args.get("q", "").strip()
    language_filter = request.args.get("language_filter", "").strip()
    tag_filter = request.args.get("tag_filter", "").strip()
    rows, available_languages, available_tags = _project_catalog(db, q, language_filter, tag_filter)
    return render_template("projects.html", projects=rows, query=q, language_filter=language_filter, tag_filter=tag_filter, available_languages=available_languages, available_tags=available_tags)

@app.post("/projects/<int:project_id>/delete")
def delete_project(project_id):
    db=get_db(); db.execute("DELETE FROM projects WHERE id=?",(project_id,)); db.commit(); flash("Project deleted.","success"); return redirect(url_for("projects"))

@app.route("/projects/<int:project_id>/edit", methods=["GET","POST"])
def edit_project(project_id):
    db=get_db(); project=get_project(project_id)
    if not project: flash("Project not found.","error"); return redirect(url_for("projects"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        folder = request.form.get("folder_path", "").strip()
        language = request.form.get("language", project["language"]).strip() or project["language"]
        error = None
        if not name:
            error = "Enter a project name."
        elif not folder or not Path(folder).expanduser().is_dir():
            error = "Choose or enter an accessible project folder."
        if error:
            flash(error, "error")
            return render_template("project_form.html", project=project, form_data=request.form)
        folder = str(Path(folder).expanduser().resolve())
        db.execute("UPDATE projects SET name=?,description=?,folder_path=?,language=?,tags=? WHERE id=?", (name, request.form.get("description", "").strip(), folder, language, request.form.get("tags", "").strip(), project_id))
        db.commit()
        flash("Project updated.", "success")
        return redirect(url_for("project_detail", project_id=project_id))
    return render_template("project_form.html", project=project)

@app.get("/autopsy")
def autopsy_index():
    db = get_db()
    query = request.args.get("q", "").strip()
    language_filter = request.args.get("language_filter", "").strip()
    tag_filter = request.args.get("tag_filter", "").strip()
    projects, available_languages, available_tags = _project_catalog(db, query, language_filter, tag_filter)
    return render_template("projects.html", projects=projects, query=query, autopsy_mode=True, language_filter=language_filter, tag_filter=tag_filter, available_languages=available_languages, available_tags=available_tags)

@app.get("/projects/<int:project_id>")
def project_detail(project_id):
    db=get_db(); project=get_project(project_id)
    if not project: flash("Project not found.","error"); return redirect(url_for("projects"))
    db.execute("UPDATE projects SET accessed_at=CURRENT_TIMESTAMP WHERE id=?",(project_id,)); db.commit()
    return _render_project_detail(project)

def _render_project_detail(project, form_data=None, review_form=None):
    db = get_db()
    reviews = db.execute("SELECT * FROM reviews WHERE project_id=? ORDER BY created_at DESC, id DESC", (project["id"],)).fetchall()
    review_summary = db.execute("SELECT COUNT(*) count, COALESCE(AVG(rating),0) average FROM reviews WHERE project_id=?", (project["id"],)).fetchone()
    return render_template("project_detail.html", project=project, scan=get_latest_scan(project["id"]), executions=db.execute("SELECT * FROM executions WHERE project_id=? ORDER BY created_at DESC LIMIT 8",(project["id"],)).fetchall(), form_data=form_data or {}, review_form=review_form or {}, reviews=reviews, review_summary=review_summary)

@app.post("/projects/<int:project_id>/autopsy")
def autopsy(project_id):
    project=get_project(project_id)
    if not project: flash("Project not found.","error"); return redirect(url_for("projects"))
    try: scan_id=run_autopsy(project_id, project["folder_path"]); flash(f"Autopsy complete. Scan #{scan_id} saved.","success")
    except Exception as exc: flash(str(exc),"error")
    return redirect(url_for("autopsy_view",project_id=project_id))

@app.get("/projects/<int:project_id>/autopsy")
def autopsy_view(project_id):
    project = get_project(project_id)
    if not project:
        flash("Project not found.", "error")
        return redirect(url_for("projects"))
    scan = get_latest_scan(project_id)
    findings=[]
    severity=request.args.get("severity", "")
    if scan:
        query="SELECT * FROM findings WHERE scan_id=?"; params=[scan["id"]]
        if severity in {"Error", "Warning", "Info"}: query += " AND severity=?"; params.append(severity)
        query += " ORDER BY CASE severity WHEN 'Error' THEN 1 WHEN 'Warning' THEN 2 ELSE 3 END, file_path, line_number"
        findings=get_db().execute(query, params).fetchall()
    return render_template("autopsy.html", project=project, scan=scan, findings=findings)

@app.get("/tasks")
def tasks():
    rows=get_db().execute("SELECT t.*,p.name project_name FROM tasks t JOIN projects p ON p.id=t.project_id ORDER BY CASE priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, t.created_at DESC").fetchall(); return render_template("tasks.html", tasks=rows)

@app.post("/tasks/<int:task_id>")
def update_task(task_id):
    get_db().execute("UPDATE tasks SET priority=?,status=? WHERE id=?",(request.form.get("priority"),request.form.get("status"),task_id)); get_db().commit(); return redirect(url_for("tasks"))

@app.get("/history")
def history():
    db=get_db(); project_id=request.args.get("project_id",""); status=request.args.get("status",""); clauses=[]; params=[]
    if project_id: clauses.append("e.project_id=?"); params.append(project_id)
    if status: clauses.append("e.status=?"); params.append(status)
    where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
    rows=db.execute("SELECT e.*,p.name project_name FROM executions e JOIN projects p ON p.id=e.project_id"+where+" ORDER BY e.created_at DESC",params).fetchall(); return render_template("history.html", executions=rows, projects=db.execute("SELECT * FROM projects ORDER BY name").fetchall())

@app.post("/projects/<int:project_id>/sources")
def upload_sources(project_id):
    project = get_project(project_id)
    if not project:
        flash("Project not found.", "error")
        return redirect(url_for("projects"))

    files = request.files.getlist("source_files")
    saved = 0
    root = Path(project["folder_path"]).resolve()
    for uploaded in files:
        if not uploaded or not uploaded.filename:
            continue
        relative_name = Path(uploaded.filename.replace("\\", "/"))
        if relative_name.is_absolute() or ".." in relative_name.parts:
            continue
        destination = (root / relative_name).resolve()
        if root != destination and root not in destination.parents:
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        uploaded.save(destination)
        saved += 1

    if saved:
        flash(f"Added {saved} source file{'s' if saved != 1 else ''} to the vault.", "success")
    else:
        flash("Choose at least one source file to add.", "error")
    return redirect(url_for("project_detail", project_id=project_id))

@app.post("/projects/<int:project_id>/run")
def run_script(project_id):
    project = get_project(project_id)
    if not project:
        flash("Project not found.", "error")
        return redirect(url_for("projects"))
    script = request.form.get("script_path", "").strip()
    try:
        timeout = min(max(int(request.form.get("timeout", 10)), 1), 120)
        execute_script(project_id, project["folder_path"], script, timeout)
        flash("Execution recorded.", "success")
    except (TypeError, ValueError) as exc:
        flash(str(exc) or "Enter a valid timeout and Python script path.", "error")
        return _render_project_detail(project, request.form)
    except Exception as exc:
        flash(str(exc), "error")
        return _render_project_detail(project, request.form)
    return redirect(url_for("project_detail", project_id=project_id))

@app.post("/projects/<int:project_id>/reviews")
def add_review(project_id):
    project = get_project(project_id)
    if not project:
        flash("Project not found.", "error")
        return redirect(url_for("projects"))
    reviewer = request.form.get("reviewer", "").strip() or "Anonymous reviewer"
    note = request.form.get("note", "").strip()
    try:
        rating = int(request.form.get("rating", ""))
        if not 1 <= rating <= 5:
            raise ValueError
    except ValueError:
        flash("Choose a star rating from 1 to 5.", "error")
        return _render_project_detail(project, review_form=request.form)
    if not note:
        flash("Add a feedback note before saving.", "error")
        return _render_project_detail(project, review_form=request.form)
    if len(reviewer) > 100 or len(note) > 2000:
        flash("Reviewer names are limited to 100 characters and notes to 2,000 characters.", "error")
        return _render_project_detail(project, review_form=request.form)
    db = get_db()
    db.execute("INSERT INTO reviews(project_id,reviewer,rating,note) VALUES(?,?,?,?)", (project_id, reviewer, rating, note))
    db.commit()
    flash("Reviewer feedback saved.", "success")
    return redirect(url_for("project_detail", project_id=project_id) + "#reviews")

@app.get("/projects/<int:project_id>/report")
def report(project_id):
    project=get_project(project_id)
    try: path=build_report(project_id, project); return send_file(path, as_attachment=True, download_name=Path(path).name)
    except Exception as exc: flash(str(exc),"error"); return redirect(url_for("project_detail",project_id=project_id))

@app.get("/settings")
def settings(): return render_template("settings.html")

@app.route("/profile", methods=["GET", "POST"])
def profile():
    db = get_db()
    if request.method == "POST":
        try:
            values = _profile_values(request.form)
        except ValueError as exc:
            flash(str(exc), "error")
            return _render_profile(request.form)
        db.execute("UPDATE developer_profile SET full_name=?,headline=?,bio=?,skills=?,updated_at=CURRENT_TIMESTAMP WHERE id=1", (values["full_name"], values["headline"], values["bio"], values["skills"]))
        db.commit()
        flash("Developer profile saved.", "success")
        return redirect(url_for("profile"))
    saved_profile = dict(db.execute("SELECT * FROM developer_profile WHERE id=1").fetchone())
    return _render_profile(saved_profile)

def _render_profile(profile_data):
    account = get_db().execute("SELECT username FROM local_account WHERE id=1").fetchone()
    return render_template("profile.html", profile=profile_data, account=account)

@app.post("/account/password")
def change_password():
    db = get_db()
    account = db.execute("SELECT id,password_hash FROM local_account WHERE id=1").fetchone()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirmation = request.form.get("confirm_password", "")
    if not check_password_hash(account["password_hash"], current_password):
        flash("Current password is incorrect.", "error")
    elif len(new_password) < 12 or len(new_password) > 128:
        flash("Choose a new password between 12 and 128 characters.", "error")
    elif new_password != confirmation:
        flash("The new passwords do not match.", "error")
    else:
        db.execute("UPDATE local_account SET password_hash=? WHERE id=1", (generate_password_hash(new_password),))
        db.commit()
        session.clear()
        session["account_id"] = account["id"]
        session.permanent = True
        flash("Password updated.", "success")
    return redirect(url_for("profile") + "#account-security")

@app.post("/profile/import")
def import_profile():
    uploaded = request.files.get("profile_file")
    if not uploaded or not uploaded.filename:
        flash("Choose a DevVault profile JSON file to import.", "error")
        return _render_profile(dict(get_db().execute("SELECT * FROM developer_profile WHERE id=1").fetchone()))
    try:
        contents = uploaded.stream.read(65537)
        if len(contents) > 65536:
            raise ValueError("The profile file must be 64 KB or smaller.")
        document = json.loads(contents.decode("utf-8"))
        if not isinstance(document, dict):
            raise ValueError("The profile file must contain a JSON object.")
        values = _profile_values(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        flash(f"Could not import profile: {exc}", "error")
        return _render_profile(dict(get_db().execute("SELECT * FROM developer_profile WHERE id=1").fetchone()))
    db = get_db()
    db.execute("UPDATE developer_profile SET full_name=?,headline=?,bio=?,skills=?,updated_at=CURRENT_TIMESTAMP WHERE id=1", (values["full_name"], values["headline"], values["bio"], values["skills"]))
    db.commit()
    flash("Developer profile imported.", "success")
    return redirect(url_for("profile"))

@app.get("/profile/export")
def export_profile():
    profile_data = dict(get_db().execute("SELECT full_name,headline,bio,skills FROM developer_profile WHERE id=1").fetchone())
    profile_data["skills"] = [skill.strip() for skill in profile_data["skills"].split(",") if skill.strip()]
    payload = json.dumps(profile_data, ensure_ascii=False, indent=2).encode("utf-8")
    return send_file(BytesIO(payload), mimetype="application/json", as_attachment=True, download_name="devvault-profile.json")

@app.get("/portfolio/export")
def export_portfolio():
    db = get_db()
    profile_data = db.execute("SELECT * FROM developer_profile WHERE id=1").fetchone()
    projects = db.execute("""SELECT p.*,
        (SELECT total_files FROM scans s WHERE s.project_id=p.id ORDER BY s.created_at DESC,s.id DESC LIMIT 1) total_files,
        (SELECT python_files FROM scans s WHERE s.project_id=p.id ORDER BY s.created_at DESC,s.id DESC LIMIT 1) python_files,
        (SELECT physical_lines FROM scans s WHERE s.project_id=p.id ORDER BY s.created_at DESC,s.id DESC LIMIT 1) physical_lines,
        (SELECT COUNT(*) FROM executions e WHERE e.project_id=p.id) execution_count,
        (SELECT COUNT(*) FROM reviews r WHERE r.project_id=p.id) review_count,
        (SELECT AVG(rating) FROM reviews r WHERE r.project_id=p.id) review_average
        FROM projects p ORDER BY p.name COLLATE NOCASE""").fetchall()
    portfolio_projects = []
    for project in projects:
        project_data = dict(project)
        project_data["reviews"] = db.execute("SELECT reviewer,rating,note,created_at FROM reviews WHERE project_id=? ORDER BY created_at DESC,id DESC LIMIT 5", (project["id"],)).fetchall()
        portfolio_projects.append(project_data)
    response = make_response(render_template("portfolio_export.html", profile=profile_data, projects=portfolio_projects))
    response.headers["Content-Disposition"] = 'attachment; filename="devvault-portfolio.html"'
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    return response

@app.teardown_appcontext
def close_db(exception=None):
    from database import close_db as close
    close(exception)

if __name__ == "__main__": app.run(debug=True)
