from pathlib import Path
from datetime import datetime
import html, tempfile
from database import get_db, get_latest_scan

def build_report(project_id, project):
    db=get_db(); scan=get_latest_scan(project_id); findings=db.execute('SELECT * FROM findings WHERE scan_id=? ORDER BY id',(scan['id'],)).fetchall() if scan else []; tasks=db.execute('SELECT * FROM tasks WHERE project_id=? ORDER BY id',(project_id,)).fetchall(); executions=db.execute('SELECT * FROM executions WHERE project_id=? ORDER BY created_at DESC LIMIT 10',(project_id,)).fetchall()
    def esc(v): return html.escape(str(v or ''))
    findings_html=''.join(f'<tr><td>{esc(f["severity"])}</td><td>{esc(f["description"])}</td><td>{esc(f["file_path"])}</td><td>{esc(f["line_number"])}</td></tr>' for f in findings) or '<tr><td colspan="4">No findings recorded.</td></tr>'
    tasks_html=''.join(f'<li><strong>{esc(t["status"])}</strong> — {esc(t["title"])} ({esc(t["priority"])})</li>' for t in tasks) or '<li>No fix tasks recorded.</li>'
    exec_html=''.join(f'<li>{esc(e["created_at"])} — {esc(e["script_path"])} — {esc(e["status"])} ({esc(e["duration"])}s)</li>' for e in executions) or '<li>No executions recorded.</li>'
    metrics='No scan recorded.' if not scan else f'{scan["python_files"]} Python files · {scan["total_files"]} total files · {scan["total_folders"]} folders · {scan["physical_lines"]} physical lines · {scan["non_empty_lines"]} non-empty lines'
    body=f'''<!doctype html><meta charset="utf-8"><title>DevVault report — {esc(project["name"])}</title><style>body{{font:16px system-ui;max-width:1000px;margin:40px auto;color:#18221f}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccd5d0;padding:8px;text-align:left}}th{{background:#eaf3ee}}</style><h1>DevVault · {esc(project["name"])}</h1><p>{esc(project["description"])}</p><p>Generated {datetime.now().isoformat(timespec="seconds")}</p><h2>Autopsy metrics</h2><p>{metrics}</p><h2>Findings</h2><table><tr><th>Severity</th><th>Description</th><th>File</th><th>Line</th></tr>{findings_html}</table><h2>Fix tasks</h2><ul>{tasks_html}</ul><h2>Recent execution history</h2><ul>{exec_html}</ul>'''
    out=Path(tempfile.gettempdir())/f'devvault-report-{project_id}.html'; out.write_text(body,encoding='utf-8'); return out
