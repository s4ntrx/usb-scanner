$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

python -m pip install --upgrade pip
python -m pip install -e ".[gui,yara]" pyinstaller
python -m pytest -q

pyinstaller packaging/usbscan.spec --noconfirm --clean
Compress-Archive -Path dist/usbscan/* -DestinationPath dist/usbscan-windows.zip -Force
Get-FileHash dist/usbscan-windows.zip -Algorithm SHA256 | Format-List
