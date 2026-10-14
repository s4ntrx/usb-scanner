from pathlib import Path

project_root = Path(SPECPATH).parent
icon_path = project_root / "packaging" / "usbscan.ico"

analysis = Analysis(
    [str(project_root / "packaging" / "launcher.py")],
    pathex=[str(project_root)],
    datas=[(str(project_root / "usbscan" / "data"), "usbscan/data")],
    hiddenimports=["yara"],
    excludes=["tkinter", "unittest", "pytest"],
)
archive = PYZ(analysis.pure)
executable = EXE(
    archive,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="usbscan",
    console=False,
    icon=str(icon_path) if icon_path.exists() else None,
)
bundle = COLLECT(executable, analysis.binaries, analysis.datas, name="usbscan")
