from pathlib import Path
p = Path('src/py_entropy.rs')
if p.exists():
    backup = p.with_suffix('.rs.bak')
    backup.write_text(p.read_text(encoding='utf-8'), encoding='utf-8')
p.write_text('// py_entropy.rs — deaktiviert.\n// Shannon-Entropie, Zipf, Noether werden von modules/ethics_engine.py berechnet.\n// PyO3-Binding war redundant — Python-Implementierung ist ausreichend.\n', encoding='utf-8')
print('TASK3_UPDATED_py_entropy', p, 'backup->', backup if 'backup' in locals() else 'none')
# Remove py_entropy mod declaration from src/lib.rs
lib = Path('src/lib.rs')
s = lib.read_text(encoding='utf-8')
old = '\n#[cfg(feature = "python")]\npub mod py_entropy;\n'
if old in s:
    s = s.replace(old, '\n')
    lib.with_suffix('.rs.lib.bak').write_text(lib.read_text(encoding='utf-8'), encoding='utf-8')
    lib.write_text(s, encoding='utf-8')
    print('TASK3_REMOVED_mod_from_lib')
else:
    # try without cfg line
    old2 = 'pub mod py_entropy;'
    if old2 in s:
        s = s.replace(old2, '')
        lib.with_suffix('.rs.lib.bak').write_text(lib.read_text(encoding='utf-8'), encoding='utf-8')
        lib.write_text(s, encoding='utf-8')
        print('TASK3_REMOVED_mod_from_lib_simple')
    else:
        print('TASK3_no_mod_found_in_lib')
