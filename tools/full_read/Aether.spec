# -*- mode: python ; coding: utf-8 -*-

import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files


PYTHON_ROOT = Path(sys.executable).resolve().parent
DLL_DIR = PYTHON_ROOT / "DLLs"
TCL_DIR = PYTHON_ROOT / "tcl"
PYINSTALLER_HOOKS = PYTHON_ROOT / "Lib" / "site-packages" / "PyInstaller" / "hooks" / "rthooks"
LOCAL_APPDATA = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
RUNTIME_TMPDIR = LOCAL_APPDATA / "Ae"

os.environ.setdefault("TCL_LIBRARY", str(TCL_DIR / "tcl8.6"))
os.environ.setdefault("TK_LIBRARY", str(TCL_DIR / "tk8.6"))
RUNTIME_TMPDIR.mkdir(parents=True, exist_ok=True)

hiddenimports = [
    "webview",
    "tkinter",
    "_tkinter",
    "tkinter.ttk",
    "tkinter.filedialog",
    "tkinter.messagebox",
    "tkinter.simpledialog",
    "tkinter.font",
    "tkinterdnd2",
    "cv2",
    "PIL",
    "PIL._tkinter_finder",
    "sounddevice",
    "matplotlib.backends.backend_tkagg",
    "cryptography",
    "winshell",
    "win32com",
    "win32com.client",
    "pythoncom",
    "pywintypes",
]

excludes = [
    "speech_recognition",
    "pocketsphinx",
    "PyQt5",
    "PyQt6",
    "PySide2",
    "PySide6",
    "shiboken2",
    "shiboken6",
    "qtpy",
    "gi",
    "cefpython3",
    "tornado",
    "webview.platforms.qt",
    "webview.platforms.gtk",
    "webview.platforms.cocoa",
    "webview.platforms.android",
    "webview.platforms.cef",
    "matplotlib.backends.backend_qt5agg",
    "matplotlib.backends.backend_qtagg",
    "matplotlib.backends.qt_compat",
]

datas = collect_data_files("webview") + collect_data_files("matplotlib")
if (PYTHON_ROOT / "Lib" / "tkinter").exists():
    datas.append((str(PYTHON_ROOT / "Lib" / "tkinter"), "tkinter"))
if (TCL_DIR / "tcl8.6").exists():
    datas.append((str(TCL_DIR / "tcl8.6"), "_tcl_data"))
if (TCL_DIR / "tk8.6").exists():
    datas.append((str(TCL_DIR / "tk8.6"), "_tk_data"))

binaries = []
for candidate in (
    DLL_DIR / "_tkinter.pyd",
    DLL_DIR / "tcl86t.dll",
    DLL_DIR / "tk86t.dll",
):
    if candidate.exists():
        binaries.append((str(candidate), "."))

a = Analysis(
    ["start.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(PYINSTALLER_HOOKS / "pyi_rth__tkinter.py")],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

icon_path = Path("icon.ico").resolve()
icon_value = str(icon_path) if icon_path.is_file() else None

exe = EXE(
    pyz,
    a.scripts,
    [],
    name="Aether",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=str(RUNTIME_TMPDIR),
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_value,
    exclude_binaries=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Aether",
)
