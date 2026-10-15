from pathlib import Path
import ast
from database import get_db

EXCLUDED={'.git','__pycache__','.venv','venv','node_modules','build','dist'}
def iter_files(root):
    for path in root.rglob('*'):
        if path.is_symlink() or any(part in EXCLUDED for part in path.relative_to(root).parts): continue
        if path.is_file(): yield path

def run_autopsy(project_id, folder_path):
    root = Path(folder_path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError('The registered folder is not accessible.')
    db = get_db()
    if not db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
        raise ValueError('The selected project no longer exists.')
    files=list(iter_files(root)); py=[p for p in files if p.suffix.lower()=='.py']; db=get_db(); metrics={'total_files':len(files),'total_folders':sum(p.is_dir() for p in root.rglob('*') if not p.is_symlink() and not any(x in EXCLUDED for x in p.relative_to(root).parts)),'python_files':len(py),'physical_lines':0,'non_empty_lines':0}
    scan=db.execute("INSERT INTO scans(project_id,total_files,total_folders,python_files,physical_lines,non_empty_lines) VALUES(?,?,?,?,?,?)",(project_id,metrics['total_files'],metrics['total_folders'],len(py),0,0)); scan_id=scan.lastrowid
    for path in py:
        rel=str(path.relative_to(root)); text=path.read_text(encoding='utf-8',errors='replace'); lines=text.splitlines(); metrics['physical_lines']+=len(lines); metrics['non_empty_lines']+=sum(bool(x.strip()) for x in lines)
        for i,line in enumerate(lines,1):
            marker=next((m for m in ('FIXME','TODO') if m in line),None)
            if marker: add_finding(db,scan_id,'Warning',f'{marker} marker found',rel,i,'Review or resolve this marker before release.')
        try: tree=ast.parse(text,filename=rel)
        except SyntaxError as exc: add_finding(db,scan_id,'Error',f'Syntax error: {exc.msg}',rel,exc.lineno,'Open the file and correct the syntax before running it.'); continue
        imports={n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n,ast.ImportFrom) and n.module} | {a.name.split('.')[0] for n in ast.walk(tree) if isinstance(n,ast.Import) for a in n.names}
        local={p.stem for p in py} | {p.parent.name for p in py}
        for name in sorted(imports & local): add_finding(db,scan_id,'Info',f'Local module import identified: {name}',rel,None,'Review local module boundaries when refactoring.')
    db.execute("UPDATE scans SET physical_lines=?,non_empty_lines=? WHERE id=?",(metrics['physical_lines'],metrics['non_empty_lines'],scan_id))
    for finding in db.execute("SELECT * FROM findings WHERE scan_id=?",(scan_id,)).fetchall():
        priority='High' if finding['severity']=='Error' else 'Medium' if finding['severity']=='Warning' else 'Low'; title=finding['description'][:100]
        db.execute("INSERT INTO tasks(project_id,finding_id,title,description,file_path,line_number,priority) VALUES(?,?,?,?,?,?,?)",(project_id,finding['id'],title,finding['suggestion'],finding['file_path'],finding['line_number'],priority))
    db.commit(); return scan_id

def add_finding(db,scan_id,severity,description,file_path,line_number,suggestion): db.execute("INSERT INTO findings(scan_id,severity,description,file_path,line_number,suggestion) VALUES(?,?,?,?,?,?)",(scan_id,severity,description,file_path,line_number,suggestion))
