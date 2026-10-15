from pathlib import Path
import subprocess, sys, time
from database import get_db
MAX_OUTPUT=20000

def execute_script(project_id, folder_path, script_path, timeout=10):
    root = Path(folder_path).expanduser().resolve()
    target = (root / script_path).resolve()
    if not root.is_dir():
        raise ValueError('The registered project folder is not accessible.')
    if root not in target.parents or not target.is_file():
        raise ValueError('Script path must point to a file inside the registered project.')
    if target.suffix.lower() != '.py':
        raise ValueError('Only Python scripts can be executed.')
    start=time.perf_counter(); status='Success'; exit_code=None; stdout=''; stderr=''
    try:
        proc=subprocess.run([sys.executable,str(target)],cwd=root,capture_output=True,text=True,timeout=timeout,shell=False)
        exit_code=proc.returncode; stdout=proc.stdout[:MAX_OUTPUT]; stderr=proc.stderr[:MAX_OUTPUT]; status='Success' if exit_code==0 else 'Failed'
    except subprocess.TimeoutExpired as exc:
        status='Timed out'; stdout=(exc.stdout or '')[:MAX_OUTPUT] if isinstance(exc.stdout,str) else ''; stderr='Execution exceeded the configured timeout.'
    except Exception as exc: status='Error'; stderr=str(exc)
    db=get_db(); db.execute('INSERT INTO executions(project_id,script_path,duration,exit_code,status,stdout,stderr) VALUES(?,?,?,?,?,?,?)',(project_id,str(target.relative_to(root)),time.perf_counter()-start,exit_code,status,stdout,stderr)); db.commit()

def cancel_execution(): return False
