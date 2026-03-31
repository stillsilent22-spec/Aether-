import os,sys,shutil,time
from pathlib import Path
old='6c9e2fcad95e2bd0'
new='d19ef200316f7f4f'
root=Path.cwd()
backup_root=Path.home()/'.aether_key_backups'/time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
backup_root.mkdir(parents=True, exist_ok=True)
modified=[]
renamed=[]
for p in root.glob('data/**'):
    try:
        if not p.is_file():
            continue
        rel=p.relative_to(root)
        txt=p.read_text(encoding='utf-8',errors='ignore')
        if old in txt:
            dest=backup_root/rel
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(str(p),str(dest))
            newtxt=txt.replace(old,new)
            p.write_text(newtxt,encoding='utf-8')
            modified.append(str(rel))
        # rename files containing old in name
        if old in p.name:
            newname=p.name.replace(old,new)
            newpath=p.with_name(newname)
            try:
                p.rename(newpath)
                renamed.append((str(rel), str(newpath.relative_to(root))))
            except Exception:
                pass
    except Exception:
        continue
print('BACKUP_DIR='+str(backup_root))
print('MODIFIED_COUNT='+str(len(modified)))
for m in modified[:200]: print('M:'+m)
if renamed:
    for a,b in renamed[:200]: print('REN:'+a+' -> '+b)
