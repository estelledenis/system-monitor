@echo off
cd /d %~dp0
python -m pytest tests --maxfail=1 --disable-warnings --tb=short
pause
