@echo off
SET DIR=%~dp0

python -m venv "%DIR%venv"
CALL "%DIR%venv\Scripts\activate.bat"
python -m pip install --upgrade pip
pip install -r "%DIR%requirements.txt"
python "%DIR%dashboard.py"
