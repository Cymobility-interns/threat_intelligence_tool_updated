@echo off

REM ---- Project root ----
cd /d "%~dp0"

REM ---- Activate venv ----
call venv\Scripts\activate.bat

REM ---- Make project root visible to Python ----
set PYTHONPATH="%~dp0"

REM ---- Run pipeline ----
python run_pipeline.py >> pipeline.log 2>&1