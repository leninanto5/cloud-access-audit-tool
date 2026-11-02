@echo off
REM Runs the audit with the demo data (Windows). Add your own options after the command.
cd /d "%~dp0.."
python audit_report.py --demo %*
pause
